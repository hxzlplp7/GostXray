#!/bin/bash
# GOST v3 + Xray 中转脚本 - MrChrootBSD Root 版本
# 适用于通过 MrChrootBSD 获取 root 后的 FreeBSD 环境
# 支持协议: VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, SOCKS, HTTP
# 快捷命令: gostxray

Green="\033[32m" && Red="\033[31m" && Yellow="\033[33m"
Cyan="\033[36m" && Reset="\033[0m"
Info="${Green}[信息]${Reset}"
Error="${Red}[错误]${Reset}"
Warning="${Yellow}[警告]${Reset}"
Tip="${Cyan}[提示]${Reset}"

shell_version="3.4.0-root"
gost_version="3.0.0"

# ==================== 环境检测 ====================
# 检测是否在 MrChrootBSD 环境中
detect_environment() {
    if [ "$(id -u)" = "0" ]; then
        echo -e "${Info} 当前以 root 权限运行"
        IS_ROOT=true
    else
        echo -e "${Warning} 当前非 root 用户"
        IS_ROOT=false
    fi
    
    # 检测是否在 chroot 环境中
    if [ -f /proc/1/root ] && [ "$(readlink /proc/1/root)" != "/" ]; then
        echo -e "${Info} 检测到 chroot 环境"
        IN_CHROOT=true
    else
        IN_CHROOT=false
    fi
    
    # 检测是否在 MrChrootBSD 环境
    if [ -f "$HOME/.mrchroot_env" ]; then
        echo -e "${Info} 检测到 MrChrootBSD 环境"
        IS_MRCHROOT=true
    else
        IS_MRCHROOT=false
    fi
}

# Root 环境目录
ROOT_HOME="${HOME:-/root}"
GOST_DIR="${ROOT_HOME}/.gost"
GOST_BIN="${GOST_DIR}/gost"
GOST_CONF="${GOST_DIR}/config.yaml"
RAW_CONF="${GOST_DIR}/rawconf"
PORT_CONF="${GOST_DIR}/ports.conf"
PID_FILE="${GOST_DIR}/gost.pid"
LOG_FILE="${GOST_DIR}/gost.log"
SCRIPT_PATH="/usr/local/bin/gostxray"

# ==================== 初始化 ====================
init_dirs() {
    mkdir -p "$GOST_DIR"
    mkdir -p "/usr/local/bin"
    touch "$RAW_CONF" "$PORT_CONF"
}

# ==================== 快捷命令安装 ====================
install_shortcut() {
    echo -e "${Info} 安装快捷命令..."
    
    local current_script=$(readlink -f "$0" 2>/dev/null || echo "$0")
    
    if [ "$IS_ROOT" = true ]; then
        cp "$current_script" "$SCRIPT_PATH"
        chmod +x "$SCRIPT_PATH"
        echo -e "${Info} 快捷命令安装完成！"
        echo -e "${Tip} 可以直接输入 ${Green}gostxray${Reset} 进入管理菜单"
    else
        # 非 root 下安装到用户目录
        mkdir -p "$HOME/bin"
        cp "$current_script" "$HOME/bin/gostxray"
        chmod +x "$HOME/bin/gostxray"
        
        if ! grep -q 'HOME/bin' "$HOME/.profile" 2>/dev/null; then
            echo 'export PATH="$HOME/bin:$PATH"' >> "$HOME/.profile"
        fi
        
        echo -e "${Info} 快捷命令安装完成！"
        echo -e "${Tip} 请运行: ${Green}source ~/.profile${Reset}"
        echo -e "${Tip} 然后可以输入 ${Green}gostxray${Reset} 进入管理菜单"
    fi
}

# ==================== 系统检测 ====================
check_system() {
    local os=$(uname -s)
    local arch=$(uname -m)
    
    case $arch in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        i386|i686) ARCH="386" ;;
        *) echo -e "${Error} 不支持的架构: $arch"; exit 1 ;;
    esac
    
    echo -e "${Info} 系统: $os ($arch)"
    
    # 检测是否为 FreeBSD
    if [[ "$os" == "FreeBSD" ]]; then
        OS_TYPE="freebsd"
        PKG_MANAGER="pkg"
    elif [[ "$os" == "Linux" ]]; then
        OS_TYPE="linux"
        if command -v apt &>/dev/null; then
            PKG_MANAGER="apt"
        elif command -v yum &>/dev/null; then
            PKG_MANAGER="yum"
        fi
    fi
}

# ==================== 端口管理 (Root 版本) ====================
# 在 root 环境下可以直接绑定端口，无需 devil

check_port() {
    local port=$1
    if command -v sockstat &>/dev/null; then
        sockstat -4 -l 2>/dev/null | grep -q ":$port " && return 1
    elif command -v netstat &>/dev/null; then
        netstat -an 2>/dev/null | grep -q "[:.]$port " && return 1
    elif command -v ss &>/dev/null; then
        ss -tlnp 2>/dev/null | grep -q ":$port " && return 1
    fi
    return 0
}

get_random_port() {
    local min=$1
    local max=$2
    echo $((RANDOM % (max - min + 1) + min))
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
    
    if command -v nc &>/dev/null; then
        if timeout ${timeout} nc -z -w 2 "$host" "$port" >/dev/null 2>&1; then
            echo -e "${Info} ✓ 端口可达"
            return 0
        fi
    fi
    
    echo -e "${Warning} ✗ 端口不可达"
    return 1
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

# 检查是否为不支持中转的协议
check_unsupported_protocol() {
    local link="$1"
    local proto="$2"
    
    if [[ "$link" == *"reality"* ]] || [[ "$link" == *"pbk="* ]]; then
        echo -e ""
        echo -e "${Red}✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖${Reset}"
        echo -e "${Red}  警告: 检测到 VLESS-Reality 协议!${Reset}"
        echo -e "${Red}✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖${Reset}"
        echo -e "${Yellow}Reality 协议无法通过中转！${Reset}"
        return 1
    fi
    
    if [[ "$proto" == "hysteria2" ]] || [[ "$proto" == "tuic" ]]; then
        echo -e ""
        echo -e "${Cyan}提示: ${proto^^} 使用 UDP 协议${Reset}"
        echo -e "${Cyan}将配置 UDP 中转${Reset}"
    fi
    
    return 0
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
    
    echo -e "${Info} 正在下载 GOST v3..."
    
    local url="https://github.com/go-gost/gost/releases/download/v${gost_version}/gost_${gost_version}_${OS_TYPE}_${ARCH}.tar.gz"
    
    cd "$GOST_DIR"
    
    if command -v curl &>/dev/null; then
        curl -sL "$url" -o gost.tar.gz
    elif command -v wget &>/dev/null; then
        wget -q "$url" -O gost.tar.gz
    elif command -v fetch &>/dev/null; then
        fetch -q "$url" -o gost.tar.gz 2>/dev/null
    else
        echo -e "${Error} 无法下载，请手动下载: $url"
        return 1
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
    
    # 安装快捷命令
    install_shortcut
}

# ==================== GOST 配置生成 ====================
generate_gost_config() {
    local port="$1"
    local host="$2"
    local dport="$3"
    local proto="${4:-tcp}"
    
    cat <<EOF
  - name: relay-${port}
    addr: ":${port}"
    handler:
      type: ${proto}
    listener:
      type: ${proto}
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
    local proto="${4:-tcp}"
    
    local config=$(generate_gost_config "$port" "$host" "$dport" "$proto")
    
    if grep -q "^services: \[\]$" "$GOST_CONF" 2>/dev/null; then
        cat > "$GOST_CONF" << EOF
services:
${config}
EOF
    else
        echo "$config" >> "$GOST_CONF"
    fi
    
    echo "gost|${proto}|${port}|${host}|${dport}" >> "$RAW_CONF"
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
    
    nohup "$GOST_BIN" -C "$GOST_CONF" > "$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"
    
    sleep 1
    if kill -0 $(cat "$PID_FILE") 2>/dev/null; then
        echo -e "${Info} GOST 启动成功 (PID: $(cat $PID_FILE))"
    else
        echo -e "${Error} GOST 启动失败，查看日志: $LOG_FILE"
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

# ==================== 日志管理 ====================
show_log_menu() {
    echo -e ""
    echo -e "${Green}========== 日志管理 ==========${Reset}"
    echo -e "[1] 查看最新日志 (50行)"
    echo -e "[2] 查看全部日志"
    echo -e "[3] 实时查看日志 (Ctrl+C 退出)"
    echo -e "[4] 清空日志"
    echo -e "[0] 返回"
    echo -e "${Green}==============================${Reset}"
    read -p "请选择 [0-4]: " log_choice
    
    case "$log_choice" in
        1)
            if [ -f "$LOG_FILE" ]; then
                echo -e ""
                echo -e "${Cyan}========== 最新 50 行日志 ==========${Reset}"
                tail -50 "$LOG_FILE"
                echo -e "${Cyan}=================================${Reset}"
            else
                echo -e "${Warning} 日志文件不存在"
            fi
            ;;
        2)
            if [ -f "$LOG_FILE" ]; then
                echo -e ""
                echo -e "${Cyan}========== 全部日志 ==========${Reset}"
                cat "$LOG_FILE"
                echo -e "${Cyan}============================${Reset}"
            else
                echo -e "${Warning} 日志文件不存在"
            fi
            ;;
        3)
            if [ -f "$LOG_FILE" ]; then
                echo -e ""
                echo -e "${Info} 实时查看日志，按 Ctrl+C 退出..."
                tail -f "$LOG_FILE"
            else
                echo -e "${Warning} 日志文件不存在"
            fi
            ;;
        4)
            if [ -f "$LOG_FILE" ]; then
                read -p "确定要清空日志吗? [y/N]: " confirm
                if [[ $confirm =~ ^[Yy]$ ]]; then
                    cat /dev/null > "$LOG_FILE"
                    echo -e "${Info} 日志已清空"
                fi
            else
                echo -e "${Warning} 日志文件不存在"
            fi
            ;;
        0|"")
            return
            ;;
        *)
            echo -e "${Error} 无效选择"
            ;;
    esac
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
        
        if ! check_unsupported_protocol "$node_link" "$proto"; then
            read -p "是否仍要继续? [y/N]: " force_continue
            [[ ! $force_continue =~ ^[Yy]$ ]] && return 1
        fi
        
        port_type=$(detect_protocol_type "$proto")
        echo -e "${Info} 端口类型: ${Green}${port_type^^}${Reset}"
        
        parsed=$(parse_node "$node_link")
        local target=$(get_target "$proto" "$parsed")
        IFS='|' read -r target_host target_port <<< "$target"
        
        echo -e "${Info} 目标: ${Green}${target_host}:${target_port}${Reset}"
        
        if ! check_port_connectivity "$target_host" "$target_port" 3; then
            echo -e "${Warning} 目标端口不可达"
            read -p "是否仍要添加? [y/N]: " confirm
            [[ ! $confirm =~ ^[Yy]$ ]] && return 1
        fi
    else
        read -p "目标地址: " target_host
        read -p "目标端口: " target_port
    fi
    
    # 端口配置
    echo -e ""
    echo -e "${Info} 端口配置 (类型: ${port_type^^}):"
    echo -e "[1] 随机端口"
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
            echo -e "${Info} 分配端口: ${Green}$local_port (${port_type^^})${Reset}"
            ;;
        2)
            read -p "请输入端口: " local_port
            if ! check_port $local_port; then
                echo -e "${Warning} 端口可能已被占用"
            fi
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
    
    add_relay "$local_port" "$target_host" "$target_port" "$port_type"
    restart_gost
    
    echo -e ""
    echo -e "${Green}===========================================${Reset}"
    echo -e "${Info} 中转配置完成!"
    echo -e "${Green}===========================================${Reset}"
    echo -e " 本机IP:    ${Cyan}${my_ip}${Reset}"
    echo -e " 本地端口:  ${Cyan}${local_port} (${port_type})${Reset}"
    echo -e " 目标地址:  ${target_host}:${target_port}"
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
    sed -i '' "${num}d" "$RAW_CONF"
    
    sed -i "/^${port}$/d" "$PORT_CONF" 2>/dev/null || \
    sed -i '' "/^${port}$/d" "$PORT_CONF"
    
    # 重建配置
    cat > "$GOST_CONF" << 'EOF'
services: []
EOF
    
    while IFS='|' read -r type proto port host dport; do
        local config=$(generate_gost_config "$port" "$host" "$dport" "$proto")
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
    
    if [ -f "$SCRIPT_PATH" ]; then
        rm -f "$SCRIPT_PATH"
        echo -e "${Info} 已删除快捷命令 $SCRIPT_PATH"
    fi
    
    if [ -f "$HOME/bin/gostxray" ]; then
        rm -f "$HOME/bin/gostxray"
        echo -e "${Info} 已删除用户快捷命令"
    fi
    
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
    
    # 显示环境信息
    if [ "$IS_ROOT" = true ]; then
        echo -e " 权限: ${Green}Root${Reset}"
    else
        echo -e " 权限: ${Yellow}非 Root${Reset}"
    fi
    
    echo -e "${Green}================================================${Reset}"
}

# ==================== 主菜单 ====================
show_menu() {
    clear
    show_status
    
    echo -e "
${Green}========================================================${Reset}
   GOST v3 中转脚本 - MrChrootBSD Root 版 ${Red}[${shell_version}]${Reset}
${Green}========================================================${Reset}
 ${Cyan}支持: VLESS VMess Trojan SS Hy2 TUIC (不支持: Reality)${Reset}
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
 ${Green}0.${Reset}  退出
${Green}========================================================${Reset}
"
    read -p " 请选择 [0-9]: " num
    
    case "$num" in
        1) install_gost ;;
        2) uninstall ;;
        3) start_gost ;;
        4) stop_gost ;;
        5) restart_gost ;;
        6) show_log_menu ;;
        7) add_relay_config ;;
        8) show_config ;;
        9) delete_config ;;
        0) exit 0 ;;
        *) echo -e "${Error} 无效选择" ;;
    esac
    
    echo -e ""
    read -p "按回车继续..."
}

# ==================== 主程序 ====================
main() {
    detect_environment
    init_dirs
    
    while true; do
        show_menu
    done
}

main
