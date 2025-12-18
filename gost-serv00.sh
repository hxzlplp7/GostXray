#!/bin/bash
# GOST v3 + Xray 中转脚本 - Serv00/HostUno 版本
# 适用于 FreeBSD 非 root 环境
# 支持协议: VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, SOCKS, HTTP
# 快捷命令: gostxray

Green="\033[32m" && Red="\033[31m" && Yellow="\033[33m"
Cyan="\033[36m" && Reset="\033[0m"
Info="${Green}[信息]${Reset}"
Error="${Red}[错误]${Reset}"
Warning="${Yellow}[警告]${Reset}"
Tip="${Cyan}[提示]${Reset}"

shell_version="3.2.0-serv00"
gost_version="3.0.0"

# Serv00 用户目录
USER_HOME="$HOME"
GOST_DIR="$USER_HOME/.gost"
GOST_BIN="$GOST_DIR/gost"
GOST_CONF="$GOST_DIR/config.yaml"
RAW_CONF="$GOST_DIR/rawconf"
PORT_CONF="$GOST_DIR/ports.conf"
PID_FILE="$GOST_DIR/gost.pid"
SCRIPT_PATH="$HOME/bin/gostxray"

# ==================== 初始化 ====================
init_dirs() {
    mkdir -p "$GOST_DIR"
    mkdir -p "$HOME/bin"
    touch "$RAW_CONF" "$PORT_CONF"
}

# ==================== 快捷命令安装 ====================
install_shortcut() {
    echo -e "${Info} 安装快捷命令..."
    
    local current_script=$(readlink -f "$0" 2>/dev/null || echo "$0")
    
    cp "$current_script" "$SCRIPT_PATH"
    chmod +x "$SCRIPT_PATH"
    
    # 添加到 PATH
    if ! grep -q 'HOME/bin' "$HOME/.profile" 2>/dev/null; then
        echo 'export PATH="$HOME/bin:$PATH"' >> "$HOME/.profile"
    fi
    
    echo -e "${Info} 快捷命令安装完成！"
    echo -e "${Tip} 请运行: ${Green}source ~/.profile${Reset}"
    echo -e "${Tip} 然后可以输入 ${Green}gostxray${Reset} 进入管理菜单"
}

# ==================== 系统检测 ====================
check_system() {
    local os=$(uname -s)
    local arch=$(uname -m)
    
    if [[ "$os" != "FreeBSD" ]]; then
        echo -e "${Warning} 当前系统: $os，此脚本专为 FreeBSD (Serv00/HostUno) 设计"
    fi
    
    case $arch in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        i386|i686) ARCH="386" ;;
        *) echo -e "${Error} 不支持的架构: $arch"; exit 1 ;;
    esac
    
    echo -e "${Info} 系统: $os ($arch)"
}

# ==================== Devil 端口管理 (Serv00/HostUno) ====================

# 检查端口是否已被 devil 添加
check_devil_port() {
    local port=$1
    local port_type=$2
    
    if ! command -v devil >/dev/null 2>&1; then
        return 1
    fi
    
    devil port list | grep -q "${port_type} ${port}"
    return $?
}

# 使用 devil 添加端口
add_devil_port() {
    local port=$1
    local port_type=$2
    local description=$3
    local max_retries=${4:-5}
    
    if ! command -v devil >/dev/null 2>&1; then
        echo -e "${Warning} devil 命令不可用，跳过端口添加" >&2
        return 0
    fi
    
    if check_devil_port "$port" "$port_type"; then
        echo -e "${Info} 端口 ${port_type}/${port} 已存在" >&2
        return 0
    fi
    
    local retry=0
    while [ $retry -lt $max_retries ]; do
        echo -e "${Yellow}正在添加端口 ${port_type}/${port}... (尝试 $((retry+1))/${max_retries})${Reset}" >&2
        
        local result=$(devil port add ${port_type} ${port} "${description}" 2>&1)
        
        if [[ $? -eq 0 ]] || echo "$result" | grep -qi "success\|已添加"; then
            echo -e "${Info} 端口 ${port_type}/${port} 添加成功" >&2
            return 0
        elif echo "$result" | grep -qi "already\|exists\|已存在"; then
            echo -e "${Info} 端口 ${port_type}/${port} 已存在" >&2
            return 0
        else
            echo -e "${Error} 添加失败: $result" >&2
            ((retry++))
            [ $retry -lt $max_retries ] && sleep 1
        fi
    done
    
    echo -e "${Error} 端口添加失败" >&2
    return 1
}

# 获取随机端口并添加到 devil
get_random_devil_port() {
    local port_type=$1
    local description=$2
    local min_port=${3:-10000}
    local max_port=${4:-65000}
    local max_attempts=50
    
    if ! command -v devil >/dev/null 2>&1; then
        echo $((RANDOM % (max_port - min_port + 1) + min_port))
        return 0
    fi
    
    local attempt=0
    while [ $attempt -lt $max_attempts ]; do
        local port=$((RANDOM % (max_port - min_port + 1) + min_port))
        
        if ! sockstat -l | grep -q ":$port "; then
            if add_devil_port "$port" "$port_type" "$description"; then
                echo "$port"
                return 0
            fi
        fi
        ((attempt++))
    done
    
    return 1
}

# 检测协议类型 (tcp/udp)
detect_protocol_type() {
    local protocol=$1
    case "$protocol" in
        hysteria2|hy2|tuic|quic) echo "udp" ;;
        *) echo "tcp" ;;
    esac
}

# 检查端口连通性
check_port_connectivity() {
    local host=$1
    local port=$2
    local timeout=${3:-3}
    
    echo -e "${Info} 检查 ${host}:${port} 连通性..."
    
    if command -v nc >/dev/null 2>&1; then
        if timeout ${timeout} nc -z -w 2 "$host" "$port" >/dev/null 2>&1; then
            echo -e "${Info} ✓ 端口可达"
            return 0
        fi
    fi
    
    echo -e "${Warning} ✗ 端口不可达"
    return 1
}

# ==================== 端口管理 ====================
get_random_port() {
    local min=$1
    local max=$2
    echo $((RANDOM % (max - min + 1) + min))
}

check_port() {
    local port=$1
    if sockstat -4 -l 2>/dev/null | grep -q ":$port " || \
       netstat -an 2>/dev/null | grep -q "[:.]$port "; then
        return 1
    fi
    return 0
}

read_port_config() {
    echo -e ""
    echo -e "${Info} 端口配置:"
    echo -e "[1] 随机端口 (10000-65535)"
    echo -e "[2] 手动指定端口"
    read -p "请选择 [默认1]: " port_mode
    port_mode=${port_mode:-1}
    
    case $port_mode in
        1)
            local_port=$(get_random_port 10000 65535)
            local retry=0
            while ! check_port $local_port && [ $retry -lt 20 ]; do
                local_port=$(get_random_port 10000 65535)
                ((retry++))
            done
            echo -e "${Info} 分配端口: ${Green}$local_port${Reset}"
            ;;
        2)
            read -p "请输入端口: " local_port
            if ! check_port $local_port; then
                echo -e "${Warning} 端口 $local_port 可能已被占用"
            fi
            ;;
        *)
            echo -e "${Error} 无效选择"
            return 1
            ;;
    esac
    
    echo "$local_port" >> "$PORT_CONF"
    return 0
}

# ==================== Base64 解码 ====================
base64_decode() {
    local input="$1"
    input="${input//-/+}"
    input="${input//_/\/}"
    local mod=$((${#input} % 4))
    [ $mod -eq 2 ] && input="${input}=="
    [ $mod -eq 3 ] && input="${input}="
    echo "$input" | base64 -d 2>/dev/null
}

url_decode() {
    local url="${1//+/ }"
    printf '%b' "${url//%/\\x}"
}

# ==================== 协议解析 ====================
parse_vless() {
    local link="${1#vless://}"
    local uuid="${link%%@*}"
    local rest="${link#*@}"
    local host_port="${rest%%\?*}"
    local host="${host_port%%:*}"
    local port="${host_port##*:}"
    port="${port%%#*}"
    
    local params="${rest#*\?}"
    local type="" security="" sni="" path="" flow=""
    while IFS='=' read -r key value; do
        value=$(url_decode "$value")
        case $key in
            type) type="$value" ;;
            security) security="$value" ;;
            sni) sni="$value" ;;
            path) path="$value" ;;
            flow) flow="$value" ;;
        esac
    done <<< "$(echo "$params" | tr '&' '\n' | cut -d'#' -f1)"
    
    echo "vless|$uuid|$host|$port|$type|$security|$sni|$path|$flow"
}

parse_vmess() {
    local link="${1#vmess://}"
    local decoded=$(base64_decode "$link")
    
    if command -v jq &>/dev/null; then
        local host=$(echo "$decoded" | jq -r '.add // ""')
        local port=$(echo "$decoded" | jq -r '.port // ""')
        local uuid=$(echo "$decoded" | jq -r '.id // ""')
        local net=$(echo "$decoded" | jq -r '.net // "tcp"')
        local tls=$(echo "$decoded" | jq -r '.tls // ""')
        local sni=$(echo "$decoded" | jq -r '.sni // ""')
        local path=$(echo "$decoded" | jq -r '.path // ""')
        local aid=$(echo "$decoded" | jq -r '.aid // "0"')
        echo "vmess|$uuid|$host|$port|$net|$tls|$sni|$path|$aid"
    else
        # 简单解析
        local host=$(echo "$decoded" | grep -o '"add"[^,]*' | cut -d'"' -f4)
        local port=$(echo "$decoded" | grep -o '"port"[^,]*' | sed 's/[^0-9]//g')
        echo "vmess||$host|$port|||||"
    fi
}

parse_trojan() {
    local link="${1#trojan://}"
    local password="${link%%@*}"
    local rest="${link#*@}"
    local host_port="${rest%%\?*}"
    local host="${host_port%%:*}"
    local port="${host_port##*:}"
    port="${port%%#*}"
    
    local params="${rest#*\?}"
    local sni="" type=""
    while IFS='=' read -r key value; do
        case $key in
            sni) sni="$value" ;;
            type) type="$value" ;;
        esac
    done <<< "$(echo "$params" | tr '&' '\n' | cut -d'#' -f1)"
    
    echo "trojan|$password|$host|$port|$type|$sni"
}

parse_ss() {
    local link="${1#ss://}"
    local method="" password="" host="" port=""
    
    if [[ "$link" == *"@"* ]]; then
        local encoded="${link%%@*}"
        local decoded=$(base64_decode "$encoded")
        method="${decoded%%:*}"
        password="${decoded#*:}"
        local host_part="${link#*@}"
        host="${host_part%%:*}"
        port="${host_part##*:}"
        port="${port%%#*}"
    else
        local decoded=$(base64_decode "${link%%#*}")
        method="${decoded%%:*}"
        local rest="${decoded#*:}"
        password="${rest%%@*}"
        local hp="${rest#*@}"
        host="${hp%%:*}"
        port="${hp##*:}"
    fi
    
    echo "ss|$method|$password|$host|$port"
}

parse_hysteria2() {
    local link="${1#hysteria2://}"
    link="${link#hy2://}"
    local password="${link%%@*}"
    local rest="${link#*@}"
    local host_port="${rest%%\?*}"
    local host="${host_port%%:*}"
    local port="${host_port##*:}"
    port="${port%%#*}"
    
    local params="${rest#*\?}"
    local sni="" insecure=""
    while IFS='=' read -r key value; do
        case $key in
            sni) sni="$value" ;;
            insecure) insecure="$value" ;;
        esac
    done <<< "$(echo "$params" | tr '&' '\n' | cut -d'#' -f1)"
    
    echo "hysteria2|$password|$host|$port|$sni|$insecure"
}

parse_tuic() {
    local link="${1#tuic://}"
    local auth="${link%%@*}"
    local uuid="${auth%%:*}"
    local password="${auth#*:}"
    local rest="${link#*@}"
    local host_port="${rest%%\?*}"
    local host="${host_port%%:*}"
    local port="${host_port##*:}"
    port="${port%%#*}"
    
    echo "tuic|$uuid|$password|$host|$port"
}

parse_socks() {
    local link="${1#socks://}"
    link="${link#socks5://}"
    local user="" pass="" host="" port=""
    
    if [[ "$link" == *"@"* ]]; then
        local auth="${link%%@*}"
        local decoded=$(base64_decode "$auth" 2>/dev/null || echo "$auth")
        user="${decoded%%:*}"
        pass="${decoded#*:}"
        local hp="${link#*@}"
        host="${hp%%:*}"
        port="${hp##*:}"
    else
        local hp="${link%%#*}"
        host="${hp%%:*}"
        port="${hp##*:}"
    fi
    port="${port%%#*}"
    
    echo "socks|$user|$pass|$host|$port"
}

# ==================== 协议识别 ====================
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
        http://*) echo "http" ;;
        *) echo "unknown" ;;
    esac
}

parse_node() {
    local link="$1"
    local proto=$(detect_protocol "$link")
    case $proto in
        vless) parse_vless "$link" ;;
        vmess) parse_vmess "$link" ;;
        trojan) parse_trojan "$link" ;;
        ss) parse_ss "$link" ;;
        hysteria2) parse_hysteria2 "$link" ;;
        tuic) parse_tuic "$link" ;;
        socks) parse_socks "$link" ;;
        *) echo "unknown" ;;
    esac
}

get_target() {
    local proto="$1"
    local parsed="$2"
    IFS='|' read -ra p <<< "$parsed"
    
    case $proto in
        vless|vmess|trojan) echo "${p[2]}|${p[3]}" ;;
        ss) echo "${p[3]}|${p[4]}" ;;
        hysteria2) echo "${p[2]}|${p[3]}" ;;
        tuic) echo "${p[3]}|${p[4]}" ;;
        socks) echo "${p[3]}|${p[4]}" ;;
    esac
}

# ==================== 中转链接生成 ====================
generate_relay_link() {
    local proto="$1"
    local parsed="$2"
    local relay_ip="$3"
    local relay_port="$4"
    
    IFS='|' read -ra p <<< "$parsed"
    
    case $proto in
        vless)
            local link="vless://${p[1]}@${relay_ip}:${relay_port}?"
            [ -n "${p[4]}" ] && link+="type=${p[4]}&"
            [ -n "${p[5]}" ] && link+="security=${p[5]}&"
            [ -n "${p[6]}" ] && link+="sni=${p[6]}&"
            [ -n "${p[7]}" ] && link+="path=${p[7]}&"
            echo "${link%&}#Relay-${p[2]}"
            ;;
        vmess)
            local json="{\"v\":\"2\",\"ps\":\"Relay-${p[2]}\",\"add\":\"${relay_ip}\",\"port\":\"${relay_port}\",\"id\":\"${p[1]}\",\"aid\":\"${p[8]:-0}\",\"net\":\"${p[4]:-tcp}\",\"type\":\"none\",\"host\":\"${p[6]}\",\"path\":\"${p[7]}\",\"tls\":\"${p[5]}\"}"
            echo "vmess://$(echo -n "$json" | base64 | tr -d '\n')"
            ;;
        trojan)
            local link="trojan://${p[1]}@${relay_ip}:${relay_port}?"
            [ -n "${p[4]}" ] && link+="type=${p[4]}&"
            [ -n "${p[5]}" ] && link+="sni=${p[5]}&"
            echo "${link%&}#Relay-${p[2]}"
            ;;
        ss)
            local auth=$(echo -n "${p[1]}:${p[2]}" | base64 | tr -d '\n')
            echo "ss://${auth}@${relay_ip}:${relay_port}#Relay-${p[3]}"
            ;;
        hysteria2)
            local link="hysteria2://${p[1]}@${relay_ip}:${relay_port}?"
            [ -n "${p[4]}" ] && link+="sni=${p[4]}&"
            echo "${link%&}#Relay-${p[2]}"
            ;;
        tuic)
            echo "tuic://${p[1]}:${p[2]}@${relay_ip}:${relay_port}#Relay-${p[3]}"
            ;;
        socks)
            if [ -n "${p[1]}" ]; then
                local auth=$(echo -n "${p[1]}:${p[2]}" | base64 | tr -d '\n')
                echo "socks://${auth}@${relay_ip}:${relay_port}#Relay-${p[3]}"
            else
                echo "socks://${relay_ip}:${relay_port}#Relay-${p[3]}"
            fi
            ;;
    esac
}

# ==================== GOST 安装 ====================
install_gost() {
    init_dirs
    check_system
    
    echo -e "${Info} 正在下载 GOST v3 for FreeBSD..."
    
    local url="https://github.com/go-gost/gost/releases/download/v${gost_version}/gost_${gost_version}_freebsd_${ARCH}.tar.gz"
    
    cd "$GOST_DIR"
    
    if command -v curl &>/dev/null; then
        curl -sL "$url" -o gost.tar.gz
    elif command -v wget &>/dev/null; then
        wget -q "$url" -O gost.tar.gz
    else
        # Serv00 可能使用 fetch
        fetch -q "$url" -o gost.tar.gz 2>/dev/null || {
            echo -e "${Error} 无法下载，请手动下载: $url"
            return 1
        }
    fi
    
    tar -xzf gost.tar.gz
    chmod +x gost
    rm -f gost.tar.gz
    
    # 初始化配置
    cat > "$GOST_CONF" << 'EOF'
services: []
EOF
    
    echo -e "${Info} GOST v3 安装完成"
    echo -e "${Info} 安装路径: $GOST_BIN"
    
    # 添加到 PATH
    if ! grep -q ".gost" "$HOME/.profile" 2>/dev/null; then
        echo 'export PATH="$HOME/.gost:$PATH"' >> "$HOME/.profile"
        echo -e "${Info} 已添加到 PATH，请运行: source ~/.profile"
    fi
}

# ==================== GOST 配置生成 ====================
generate_gost_config() {
    local port="$1"
    local host="$2"
    local dport="$3"
    
    cat << EOF
  - name: relay-${port}
    addr: ":${port}"
    handler:
      type: tcp
    listener:
      type: tcp
    forwarder:
      nodes:
        - name: target
          addr: "${host}:${dport}"
  - name: relay-${port}-udp
    addr: ":${port}"
    handler:
      type: udp
    listener:
      type: udp
    forwarder:
      nodes:
        - name: target
          addr: "${host}:${dport}"
EOF
}

add_relay() {
    local port="$1"
    local host="$2"
    local dport="$3"
    
    local config=$(generate_gost_config "$port" "$host" "$dport")
    
    if grep -q "^services: \[\]$" "$GOST_CONF" 2>/dev/null; then
        cat > "$GOST_CONF" << EOF
services:
${config}
EOF
    else
        echo "$config" >> "$GOST_CONF"
    fi
    
    echo "gost|tcp+udp|${port}|${host}|${dport}" >> "$RAW_CONF"
}

# ==================== GOST 进程管理 ====================
start_gost() {
    if [ ! -f "$GOST_BIN" ]; then
        echo -e "${Error} GOST 未安装，请先安装"
        return 1
    fi
    
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo -e "${Warning} GOST 已在运行 (PID: $pid)"
            return 0
        fi
    fi
    
    nohup "$GOST_BIN" -C "$GOST_CONF" > "$GOST_DIR/gost.log" 2>&1 &
    echo $! > "$PID_FILE"
    
    sleep 1
    if kill -0 $(cat "$PID_FILE") 2>/dev/null; then
        echo -e "${Info} GOST 启动成功 (PID: $(cat $PID_FILE))"
    else
        echo -e "${Error} GOST 启动失败，查看日志: $GOST_DIR/gost.log"
    fi
}

stop_gost() {
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            rm -f "$PID_FILE"
            echo -e "${Info} GOST 已停止"
        else
            rm -f "$PID_FILE"
            echo -e "${Warning} GOST 未在运行"
        fi
    else
        # 尝试通过进程名查找
        pkill -f "$GOST_BIN" 2>/dev/null
        echo -e "${Info} GOST 已停止"
    fi
}

restart_gost() {
    stop_gost
    sleep 1
    start_gost
}

status_gost() {
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo -e "${Green}运行中${Reset} (PID: $pid)"
            return 0
        fi
    fi
    echo -e "${Red}已停止${Reset}"
    return 1
}

# ==================== 添加中转 ====================
add_relay_config() {
    echo -e ""
    echo -e "${Info} 请选择配置方式:"
    echo -e "[1] 粘贴节点链接 (自动解析)"
    echo -e "[2] 手动输入目标地址"
    read -p "请选择 [默认1]: " input_type
    input_type=${input_type:-1}
    
    local proto="" parsed="" port_type="tcp"
    
    if [ "$input_type" == "1" ]; then
        read -p "请粘贴节点链接: " node_link
        
        if [ -z "$node_link" ]; then
            echo -e "${Error} 链接不能为空"
            return 1
        fi
        
        proto=$(detect_protocol "$node_link")
        if [ "$proto" == "unknown" ]; then
            echo -e "${Error} 无法识别的协议"
            return 1
        fi
        
        echo -e "${Info} 协议: ${Green}${proto^^}${Reset}"
        port_type=$(detect_protocol_type "$proto")
        echo -e "${Info} 端口类型: ${Green}${port_type^^}${Reset}"
        
        parsed=$(parse_node "$node_link")
        local target=$(get_target "$proto" "$parsed")
        IFS='|' read -r target_host target_port <<< "$target"
        
        echo -e "${Info} 目标: ${Green}${target_host}:${target_port}${Reset}"
        
        # 检查目标端口连通性
        if ! check_port_connectivity "$target_host" "$target_port" 3; then
            echo -e "${Warning} 目标端口不可达，可能原因:"
            echo -e "  1. 目标服务器防火墙拦截"
            echo -e "  2. 网络不通或延迟过高"
            echo -e "  3. 目标端口未开放"
            read -p "是否仍要添加? [y/N]: " confirm
            [[ ! $confirm =~ ^[Yy]$ ]] && return 1
        fi
    else
        read -p "目标地址: " target_host
        read -p "目标端口: " target_port
    fi
    
    # 端口配置 - 使用 devil 端口管理
    echo -e ""
    echo -e "${Info} 端口配置:"
    echo -e "[1] 随机端口 + 自动添加 Devil 端口"
    echo -e "[2] 手动指定端口"
    read -p "请选择 [默认1]: " port_mode
    port_mode=${port_mode:-1}
    
    case $port_mode in
        1)
            local_port=$(get_random_devil_port "$port_type" "gost-relay" 10000 65000)
            if [ -z "$local_port" ]; then
                echo -e "${Error} 获取端口失败"
                return 1
            fi
            echo -e "${Info} 分配端口: ${Green}$local_port${Reset}"
            ;;
        2)
            read -p "请输入端口: " local_port
            if ! check_port $local_port; then
                echo -e "${Warning} 端口可能已被占用"
            fi
            add_devil_port "$local_port" "$port_type" "gost-relay"
            ;;
        *)
            echo -e "${Error} 无效选择"
            return 1
            ;;
    esac
    
    echo "$local_port" >> "$PORT_CONF"
    
    # 获取本机IP
    local my_ip=$(curl -s4m5 ip.sb 2>/dev/null || curl -s4m5 ifconfig.me 2>/dev/null)
    [ -z "$my_ip" ] && my_ip="YOUR_IP"
    
    add_relay "$local_port" "$target_host" "$target_port"
    restart_gost
    
    echo -e ""
    echo -e "${Green}===========================================${Reset}"
    echo -e "${Info} 中转配置完成!"
    echo -e "${Green}===========================================${Reset}"
    echo -e " 本机IP:    ${Cyan}${my_ip}${Reset}"
    echo -e " 本地端口:  ${Cyan}${local_port} (${port_type})${Reset}"
    echo -e " 目标地址:  ${target_host}:${target_port}"
    
    # 显示 Devil 端口状态
    if command -v devil >/dev/null 2>&1; then
        if devil port list 2>/dev/null | grep -q "${port_type} ${local_port}"; then
            echo -e " Devil端口: ${Green}✓ 已添加${Reset}"
        else
            echo -e " Devil端口: ${Yellow}⚠ 未添加${Reset}"
        fi
    fi
    echo -e "${Green}===========================================${Reset}"
    
    if [ "$input_type" == "1" ] && [ -n "$parsed" ]; then
        local relay_link=$(generate_relay_link "$proto" "$parsed" "$my_ip" "$local_port")
        echo -e ""
        echo -e "${Info} 中转后的链接:"
        echo -e "${Cyan}${relay_link}${Reset}"
    fi
}

# ==================== 查看配置 ====================
show_config() {
    echo -e ""
    echo -e "${Green}==================== 当前配置 ====================${Reset}"
    
    if [ ! -f "$RAW_CONF" ] || [ ! -s "$RAW_CONF" ]; then
        echo -e "${Warning} 暂无配置"
        return
    fi
    
    printf "%-4s | %-8s | %s\n" "序号" "本地端口" "目标地址"
    echo "----------------------------------------"
    
    local i=1
    while IFS='|' read -r type proto port host dport; do
        printf "%-4s | %-8s | %s\n" "$i" "$port" "$host:$dport"
        ((i++))
    done < "$RAW_CONF"
    
    echo -e "${Green}==================================================${Reset}"
}

# ==================== 删除配置 ====================
delete_config() {
    show_config
    
    if [ ! -s "$RAW_CONF" ]; then
        return
    fi
    
    read -p "删除序号 (0取消): " num
    [ "$num" == "0" ] && return
    
    if ! [[ "$num" =~ ^[0-9]+$ ]]; then
        echo -e "${Error} 无效输入"
        return
    fi
    
    local line=$(sed -n "${num}p" "$RAW_CONF")
    if [ -z "$line" ]; then
        echo -e "${Error} 配置不存在"
        return
    fi
    
    IFS='|' read -ra p <<< "$line"
    local port="${p[2]}"
    
    sed -i "${num}d" "$RAW_CONF" 2>/dev/null || \
    sed -i '' "${num}d" "$RAW_CONF"  # BSD sed
    
    sed -i "/^${port}$/d" "$PORT_CONF" 2>/dev/null || \
    sed -i '' "/^${port}$/d" "$PORT_CONF"
    
    # 重建配置
    cat > "$GOST_CONF" << 'EOF'
services: []
EOF
    
    while IFS='|' read -r type proto port host dport; do
        local config=$(generate_gost_config "$port" "$host" "$dport")
        if grep -q "^services: \[\]$" "$GOST_CONF"; then
            cat > "$GOST_CONF" << EOF
services:
${config}
EOF
        else
            echo "$config" >> "$GOST_CONF"
        fi
    done < "$RAW_CONF"
    
    restart_gost
    echo -e "${Info} 已删除"
}

# ==================== 卸载 ====================
uninstall() {
    echo -e "${Warning} 确定卸载? [y/N]"
    read -p "" confirm
    [[ ! $confirm =~ ^[Yy]$ ]] && return
    
    stop_gost
    rm -rf "$GOST_DIR"
    sed -i '/\.gost/d' "$HOME/.profile" 2>/dev/null || \
    sed -i '' '/\.gost/d' "$HOME/.profile"
    
    echo -e "${Info} 已卸载"
}

# ==================== 状态显示 ====================
show_status() {
    echo -e ""
    echo -e "${Green}==================== 状态 ====================${Reset}"
    echo -n " GOST: "
    status_gost
    
    local count=0
    [ -f "$RAW_CONF" ] && count=$(wc -l < "$RAW_CONF" | tr -d ' ')
    echo -e " 中转数: ${Cyan}${count}${Reset}"
    
    local ip=$(curl -s4m3 ip.sb 2>/dev/null)
    echo -e " IP: ${Cyan}${ip:-获取中...}${Reset}"
    echo -e "${Green}================================================${Reset}"
}

# ==================== 主菜单 ====================
show_menu() {
    clear
    show_status
    
    echo -e "
${Green}========================================================${Reset}
   GOST v3 中转脚本 - Serv00/HostUno 版 ${Red}[${shell_version}]${Reset}
${Green}========================================================${Reset}
 ${Cyan}支持: VLESS VMess Trojan SS Hy2 TUIC SOCKS${Reset}
${Green}--------------------------------------------------------${Reset}
 ${Green}1.${Reset}  安装 GOST v3
 ${Green}2.${Reset}  卸载 GOST v3
${Green}--------------------------------------------------------${Reset}
 ${Green}3.${Reset}  启动 GOST
 ${Green}4.${Reset}  停止 GOST
 ${Green}5.${Reset}  重启 GOST
 ${Green}6.${Reset}  查看日志
${Green}--------------------------------------------------------${Reset}
 ${Green}7.${Reset}  添加中转配置
 ${Green}8.${Reset}  查看当前配置
 ${Green}9.${Reset}  删除配置
${Green}--------------------------------------------------------${Reset}
 ${Green}10.${Reset} 安装快捷命令 (gostxray)
${Green}--------------------------------------------------------${Reset}
 ${Green}0.${Reset}  退出
${Green}========================================================${Reset}
"
    read -p " 请选择 [0-10]: " num
    
    case "$num" in
        1) install_gost ;;
        2) uninstall ;;
        3) start_gost ;;
        4) stop_gost ;;
        5) restart_gost ;;
        6) 
            if [ -f "$GOST_DIR/gost.log" ]; then
                tail -50 "$GOST_DIR/gost.log"
            else
                echo -e "${Warning} 无日志"
            fi
            ;;
        7) add_relay_config ;;
        8) show_config ;;
        9) delete_config ;;
        10) install_shortcut ;;
        0) exit 0 ;;
        *) echo -e "${Error} 无效选择" ;;
    esac
    
    echo -e ""
    read -p "按回车继续..."
}

# ==================== 主程序 ====================
main() {
    init_dirs
    
    while true; do
        show_menu
    done
}

main
