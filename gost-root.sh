#!/bin/sh
# GOST v3 + Xray 中转脚本 - MrChrootBSD Root 版本 (POSIX sh 兼容)
# 适用于通过 MrChrootBSD 获取 root 后的 FreeBSD 环境
# 支持协议: VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, SOCKS, HTTP
# 快捷命令: gostxray

Green="\033[32m"
Red="\033[31m"
Yellow="\033[33m"
Cyan="\033[36m"
Reset="\033[0m"
Info="${Green}[信息]${Reset}"
Error="${Red}[错误]${Reset}"
Warning="${Yellow}[警告]${Reset}"
Tip="${Cyan}[提示]${Reset}"

shell_version="3.4.1-root-sh"
gost_version="3.0.0"

# ==================== 环境检测 ====================
detect_environment() {
    if [ "$(id -u)" = "0" ]; then
        printf "%b\n" "${Info} 当前以 root 权限运行"
        IS_ROOT=true
    else
        printf "%b\n" "${Warning} 当前非 root 用户"
        IS_ROOT=false
    fi
    
    # 检测是否在 MrChrootBSD 环境
    if [ -f "$HOME/.mrchroot_env" ] || [ -f "/root/.mrchroot_env" ]; then
        printf "%b\n" "${Info} 检测到 MrChrootBSD 环境"
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
    mkdir -p "/usr/local/bin" 2>/dev/null || mkdir -p "$HOME/bin"
    touch "$RAW_CONF" "$PORT_CONF" 2>/dev/null
}

# ==================== 快捷命令安装 ====================
install_shortcut() {
    printf "%b\n" "${Info} 安装快捷命令..."
    
    current_script="$0"
    if command -v readlink >/dev/null 2>&1; then
        current_script=$(readlink -f "$0" 2>/dev/null) || current_script="$0"
    fi
    
    if [ "$IS_ROOT" = "true" ]; then
        cp "$current_script" "$SCRIPT_PATH" 2>/dev/null
        chmod +x "$SCRIPT_PATH" 2>/dev/null
        printf "%b\n" "${Info} 快捷命令安装完成！"
        printf "%b\n" "${Tip} 可以直接输入 ${Green}gostxray${Reset} 进入管理菜单"
    else
        mkdir -p "$HOME/bin"
        cp "$current_script" "$HOME/bin/gostxray"
        chmod +x "$HOME/bin/gostxray"
        
        if ! grep -q 'HOME/bin' "$HOME/.profile" 2>/dev/null; then
            echo 'export PATH="$HOME/bin:$PATH"' >> "$HOME/.profile"
        fi
        
        printf "%b\n" "${Info} 快捷命令安装完成！"
        printf "%b\n" "${Tip} 请运行: ${Green}source ~/.profile${Reset}"
    fi
}

# ==================== 系统检测 ====================
check_system() {
    os=$(uname -s)
    arch=$(uname -m)
    
    case $arch in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        i386|i686) ARCH="386" ;;
        *) printf "%b\n" "${Error} 不支持的架构: $arch"; exit 1 ;;
    esac
    
    printf "%b\n" "${Info} 系统: $os ($arch)"
    
    # 检测是否为 FreeBSD
    case "$os" in
        FreeBSD)
            OS_TYPE="freebsd"
            PKG_MANAGER="pkg"
            ;;
        Linux)
            OS_TYPE="linux"
            if command -v apt >/dev/null 2>&1; then
                PKG_MANAGER="apt"
            elif command -v yum >/dev/null 2>&1; then
                PKG_MANAGER="yum"
            fi
            ;;
    esac
}

# ==================== 端口管理 ====================
check_port() {
    port=$1
    if command -v sockstat >/dev/null 2>&1; then
        sockstat -4 -l 2>/dev/null | grep -q ":$port " && return 1
    elif command -v netstat >/dev/null 2>&1; then
        netstat -an 2>/dev/null | grep -q "[:.]$port " && return 1
    elif command -v ss >/dev/null 2>&1; then
        ss -tlnp 2>/dev/null | grep -q ":$port " && return 1
    fi
    return 0
}

get_random_port() {
    min=$1
    max=$2
    # 使用 awk 生成随机数 (POSIX 兼容)
    awk -v min="$min" -v max="$max" 'BEGIN{srand(); print int(min+rand()*(max-min+1))}'
}

detect_protocol_type() {
    protocol=$1
    case "$protocol" in
        hysteria2|hy2|tuic|quic) echo "udp" ;;
        *) echo "tcp" ;;
    esac
}

check_port_connectivity() {
    host=$1
    port=$2
    timeout_val=${3:-3}
    
    printf "%b\n" "${Info} 检查 ${host}:${port} 连通性..."
    
    if command -v nc >/dev/null 2>&1; then
        if timeout "$timeout_val" nc -z -w 2 "$host" "$port" >/dev/null 2>&1; then
            printf "%b\n" "${Info} ✓ 端口可达"
            return 0
        fi
    fi
    
    printf "%b\n" "${Warning} ✗ 端口不可达"
    return 1
}

# ==================== Base64 解码 ====================
base64_decode() {
    input="$1"
    # 替换 URL 安全字符
    input=$(echo "$input" | sed 's/-/+/g; s/_/\//g')
    # 添加 padding
    mod=$((${#input} % 4))
    if [ "$mod" -eq 2 ]; then
        input="${input}=="
    elif [ "$mod" -eq 3 ]; then
        input="${input}="
    fi
    echo "$input" | base64 -d 2>/dev/null
}

url_decode() {
    url="$1"
    # 简单的 URL 解码
    printf '%b' "$(echo "$url" | sed 's/+/ /g; s/%\([0-9A-Fa-f][0-9A-Fa-f]\)/\\x\1/g')"
}

# ==================== 协议解析 ====================
parse_vless() {
    link="${1#vless://}"
    uuid="${link%%@*}"
    rest="${link#*@}"
    host_port="${rest%%\?*}"
    host_port="${host_port%%#*}"
    host="${host_port%%:*}"
    port="${host_port##*:}"
    # 清理端口号
    port=$(echo "$port" | sed 's/[^0-9]//g')
    
    params="${rest#*\?}"
    params="${params%%#*}"
    
    type="" security="" sni="" path="" flow=""
    
    # 解析参数
    oldIFS="$IFS"
    IFS='&'
    for param in $params; do
        key="${param%%=*}"
        value="${param#*=}"
        value=$(url_decode "$value")
        case $key in
            type) type="$value" ;;
            security) security="$value" ;;
            sni) sni="$value" ;;
            path) path="$value" ;;
            flow) flow="$value" ;;
        esac
    done
    IFS="$oldIFS"
    
    echo "vless|$uuid|$host|$port|$type|$security|$sni|$path|$flow"
}

parse_vmess() {
    link="${1#vmess://}"
    decoded=$(base64_decode "$link")
    
    if command -v jq >/dev/null 2>&1; then
        host=$(echo "$decoded" | jq -r '.add // ""')
        port=$(echo "$decoded" | jq -r '.port // ""')
        uuid=$(echo "$decoded" | jq -r '.id // ""')
        net=$(echo "$decoded" | jq -r '.net // "tcp"')
        tls=$(echo "$decoded" | jq -r '.tls // ""')
        vmsni=$(echo "$decoded" | jq -r '.sni // ""')
        vmpath=$(echo "$decoded" | jq -r '.path // ""')
        aid=$(echo "$decoded" | jq -r '.aid // "0"')
        echo "vmess|$uuid|$host|$port|$net|$tls|$vmsni|$vmpath|$aid"
    else
        host=$(echo "$decoded" | grep -o '"add"[^,]*' | cut -d'"' -f4)
        port=$(echo "$decoded" | grep -o '"port"[^,]*' | sed 's/[^0-9]//g')
        echo "vmess||$host|$port|||||"
    fi
}

parse_trojan() {
    link="${1#trojan://}"
    password="${link%%@*}"
    rest="${link#*@}"
    host_port="${rest%%\?*}"
    host_port="${host_port%%#*}"
    host="${host_port%%:*}"
    port="${host_port##*:}"
    # 清理端口号
    port=$(echo "$port" | sed 's/[^0-9]//g')
    
    params="${rest#*\?}"
    params="${params%%#*}"
    
    sni="" type=""
    
    oldIFS="$IFS"
    IFS='&'
    for param in $params; do
        key="${param%%=*}"
        value="${param#*=}"
        case $key in
            sni) sni="$value" ;;
            type) type="$value" ;;
        esac
    done
    IFS="$oldIFS"
    
    echo "trojan|$password|$host|$port|$type|$sni"
}

parse_ss() {
    link="${1#ss://}"
    method="" password="" host="" port=""
    
    case "$link" in
        *@*)
            encoded="${link%%@*}"
            decoded=$(base64_decode "$encoded")
            method="${decoded%%:*}"
            password="${decoded#*:}"
            host_part="${link#*@}"
            host="${host_part%%:*}"
            port="${host_part##*:}"
            port="${port%%#*}"
            ;;
        *)
            decoded=$(base64_decode "${link%%#*}")
            method="${decoded%%:*}"
            rest="${decoded#*:}"
            password="${rest%%@*}"
            hp="${rest#*@}"
            host="${hp%%:*}"
            port="${hp##*:}"
            ;;
    esac
    
    echo "ss|$method|$password|$host|$port"
}

parse_hysteria2() {
    link="${1#hysteria2://}"
    link="${link#hy2://}"
    password="${link%%@*}"
    rest="${link#*@}"
    host_port="${rest%%\?*}"
    host_port="${host_port%%#*}"  # 移除 # 后的注释
    host="${host_port%%:*}"
    port="${host_port##*:}"
    # 清理端口号，移除可能的 / 和其他非数字字符
    port=$(echo "$port" | sed 's/[^0-9]//g')
    
    params="${rest#*\?}"
    params="${params%%#*}"
    
    sni="" insecure=""
    
    oldIFS="$IFS"
    IFS='&'
    for param in $params; do
        key="${param%%=*}"
        value="${param#*=}"
        case $key in
            sni) sni="$value" ;;
            insecure) insecure="$value" ;;
        esac
    done
    IFS="$oldIFS"
    
    echo "hysteria2|$password|$host|$port|$sni|$insecure"
}

parse_tuic() {
    link="${1#tuic://}"
    auth="${link%%@*}"
    uuid="${auth%%:*}"
    password="${auth#*:}"
    rest="${link#*@}"
    host_port="${rest%%\?*}"
    host_port="${host_port%%#*}"
    host="${host_port%%:*}"
    port="${host_port##*:}"
    # 清理端口号
    port=$(echo "$port" | sed 's/[^0-9]//g')
    
    echo "tuic|$uuid|$password|$host|$port"
}

parse_socks() {
    link="${1#socks://}"
    link="${link#socks5://}"
    user="" pass="" host="" port=""
    
    case "$link" in
        *@*)
            auth="${link%%@*}"
            decoded=$(base64_decode "$auth" 2>/dev/null) || decoded="$auth"
            user="${decoded%%:*}"
            pass="${decoded#*:}"
            hp="${link#*@}"
            host="${hp%%:*}"
            port="${hp##*:}"
            ;;
        *)
            hp="${link%%#*}"
            host="${hp%%:*}"
            port="${hp##*:}"
            ;;
    esac
    port="${port%%#*}"
    
    echo "socks|$user|$pass|$host|$port"
}

# ==================== 协议识别 ====================
detect_protocol() {
    link="$1"
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

check_unsupported_protocol() {
    link="$1"
    proto="$2"
    
    case "$link" in
        *reality*|*pbk=*)
            printf "\n"
            printf "%b\n" "${Red}✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖${Reset}"
            printf "%b\n" "${Red}  警告: 检测到 VLESS-Reality 协议!${Reset}"
            printf "%b\n" "${Red}✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖✖${Reset}"
            printf "%b\n" "${Yellow}Reality 协议无法通过中转！${Reset}"
            return 1
            ;;
    esac
    
    case "$proto" in
        hysteria2|tuic)
            printf "\n"
            printf "%b\n" "${Cyan}提示: $proto 使用 UDP 协议${Reset}"
            printf "%b\n" "${Cyan}将配置 UDP 中转${Reset}"
            ;;
    esac
    
    return 0
}

parse_node() {
    link="$1"
    proto=$(detect_protocol "$link")
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
    proto="$1"
    parsed="$2"
    
    # 使用 cut 解析分隔的字段
    case $proto in
        vless|vmess|trojan)
            host=$(echo "$parsed" | cut -d'|' -f3)
            port=$(echo "$parsed" | cut -d'|' -f4)
            echo "${host}|${port}"
            ;;
        ss)
            host=$(echo "$parsed" | cut -d'|' -f4)
            port=$(echo "$parsed" | cut -d'|' -f5)
            echo "${host}|${port}"
            ;;
        hysteria2)
            host=$(echo "$parsed" | cut -d'|' -f3)
            port=$(echo "$parsed" | cut -d'|' -f4)
            echo "${host}|${port}"
            ;;
        tuic)
            host=$(echo "$parsed" | cut -d'|' -f4)
            port=$(echo "$parsed" | cut -d'|' -f5)
            echo "${host}|${port}"
            ;;
        socks)
            host=$(echo "$parsed" | cut -d'|' -f4)
            port=$(echo "$parsed" | cut -d'|' -f5)
            echo "${host}|${port}"
            ;;
    esac
}

# ==================== 中转链接生成 ====================
generate_relay_link() {
    proto="$1"
    parsed="$2"
    relay_ip="$3"
    relay_port="$4"
    
    case $proto in
        vless)
            p1=$(echo "$parsed" | cut -d'|' -f2)
            p2=$(echo "$parsed" | cut -d'|' -f3)
            p5=$(echo "$parsed" | cut -d'|' -f5)
            p6=$(echo "$parsed" | cut -d'|' -f6)
            p7=$(echo "$parsed" | cut -d'|' -f7)
            p8=$(echo "$parsed" | cut -d'|' -f8)
            link="vless://${p1}@${relay_ip}:${relay_port}?"
            [ -n "$p5" ] && link="${link}type=${p5}&"
            [ -n "$p6" ] && link="${link}security=${p6}&"
            [ -n "$p7" ] && link="${link}sni=${p7}&"
            [ -n "$p8" ] && link="${link}path=${p8}&"
            echo "${link%&}#Relay-${p2}"
            ;;
        vmess)
            p1=$(echo "$parsed" | cut -d'|' -f2)
            p2=$(echo "$parsed" | cut -d'|' -f3)
            p5=$(echo "$parsed" | cut -d'|' -f5)
            p6=$(echo "$parsed" | cut -d'|' -f6)
            p7=$(echo "$parsed" | cut -d'|' -f7)
            p8=$(echo "$parsed" | cut -d'|' -f8)
            p9=$(echo "$parsed" | cut -d'|' -f9)
            [ -z "$p9" ] && p9="0"
            [ -z "$p5" ] && p5="tcp"
            json="{\"v\":\"2\",\"ps\":\"Relay-${p2}\",\"add\":\"${relay_ip}\",\"port\":\"${relay_port}\",\"id\":\"${p1}\",\"aid\":\"${p9}\",\"net\":\"${p5}\",\"type\":\"none\",\"host\":\"${p7}\",\"path\":\"${p8}\",\"tls\":\"${p6}\"}"
            encoded=$(printf '%s' "$json" | base64 | tr -d '\n')
            echo "vmess://${encoded}"
            ;;
        trojan)
            p1=$(echo "$parsed" | cut -d'|' -f2)
            p2=$(echo "$parsed" | cut -d'|' -f3)
            p5=$(echo "$parsed" | cut -d'|' -f5)
            p6=$(echo "$parsed" | cut -d'|' -f6)
            link="trojan://${p1}@${relay_ip}:${relay_port}?"
            [ -n "$p5" ] && link="${link}type=${p5}&"
            [ -n "$p6" ] && link="${link}sni=${p6}&"
            echo "${link%&}#Relay-${p2}"
            ;;
        ss)
            p1=$(echo "$parsed" | cut -d'|' -f2)
            p2=$(echo "$parsed" | cut -d'|' -f3)
            p3=$(echo "$parsed" | cut -d'|' -f4)
            auth=$(printf '%s' "${p1}:${p2}" | base64 | tr -d '\n')
            echo "ss://${auth}@${relay_ip}:${relay_port}#Relay-${p3}"
            ;;
        hysteria2)
            p1=$(echo "$parsed" | cut -d'|' -f2)
            p2=$(echo "$parsed" | cut -d'|' -f3)
            p5=$(echo "$parsed" | cut -d'|' -f5)
            link="hysteria2://${p1}@${relay_ip}:${relay_port}?"
            [ -n "$p5" ] && link="${link}sni=${p5}&"
            echo "${link%&}#Relay-${p2}"
            ;;
        tuic)
            p1=$(echo "$parsed" | cut -d'|' -f2)
            p2=$(echo "$parsed" | cut -d'|' -f3)
            p3=$(echo "$parsed" | cut -d'|' -f4)
            echo "tuic://${p1}:${p2}@${relay_ip}:${relay_port}#Relay-${p3}"
            ;;
        socks)
            p1=$(echo "$parsed" | cut -d'|' -f2)
            p2=$(echo "$parsed" | cut -d'|' -f3)
            p3=$(echo "$parsed" | cut -d'|' -f4)
            if [ -n "$p1" ]; then
                auth=$(printf '%s' "${p1}:${p2}" | base64 | tr -d '\n')
                echo "socks://${auth}@${relay_ip}:${relay_port}#Relay-${p3}"
            else
                echo "socks://${relay_ip}:${relay_port}#Relay-${p3}"
            fi
            ;;
    esac
}

# ==================== GOST 安装 ====================
install_gost() {
    init_dirs
    check_system
    
    printf "%b\n" "${Info} 正在下载 GOST v3..."
    
    url="https://github.com/go-gost/gost/releases/download/v${gost_version}/gost_${gost_version}_${OS_TYPE}_${ARCH}.tar.gz"
    
    cd "$GOST_DIR" || exit 1
    
    if command -v curl >/dev/null 2>&1; then
        curl -sL "$url" -o gost.tar.gz
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$url" -O gost.tar.gz
    elif command -v fetch >/dev/null 2>&1; then
        fetch -q -o gost.tar.gz "$url" 2>/dev/null
    else
        printf "%b\n" "${Error} 无法下载，请手动下载: $url"
        return 1
    fi
    
    tar -xzf gost.tar.gz
    chmod +x gost
    rm -f gost.tar.gz
    
    # 初始化配置
    cat > "$GOST_CONF" << 'EOF'
services: []
EOF
    
    printf "%b\n" "${Info} GOST v3 安装完成"
    printf "%b\n" "${Info} 安装路径: $GOST_BIN"
    
    install_shortcut
}

# ==================== GOST 配置生成 ====================
generate_gost_config() {
    gport="$1"
    ghost="$2"
    gdport="$3"
    gproto="${4:-tcp}"
    
    cat << EOF
  - name: relay-${gport}
    addr: ":${gport}"
    handler:
      type: ${gproto}
    listener:
      type: ${gproto}
    forwarder:
      nodes:
        - name: target
          addr: "${ghost}:${gdport}"
EOF
}

add_relay() {
    aport="$1"
    ahost="$2"
    adport="$3"
    aproto="${4:-tcp}"
    
    config=$(generate_gost_config "$aport" "$ahost" "$adport" "$aproto")
    
    if grep -q "^services: \[\]$" "$GOST_CONF" 2>/dev/null; then
        cat > "$GOST_CONF" << EOF
services:
${config}
EOF
    else
        echo "$config" >> "$GOST_CONF"
    fi
    
    echo "gost|${aproto}|${aport}|${ahost}|${adport}" >> "$RAW_CONF"
}

# ==================== GOST 进程管理 ====================
start_gost() {
    if [ ! -f "$GOST_BIN" ]; then
        printf "%b\n" "${Error} GOST 未安装，请先安装"
        return 1
    fi
    
    if [ -f "$PID_FILE" ]; then
        pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            printf "%b\n" "${Warning} GOST 已在运行 (PID: $pid)"
            return 0
        fi
    fi
    
    nohup "$GOST_BIN" -C "$GOST_CONF" > "$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"
    
    sleep 1
    newpid=$(cat "$PID_FILE" 2>/dev/null)
    if kill -0 "$newpid" 2>/dev/null; then
        printf "%b\n" "${Info} GOST 启动成功 (PID: $newpid)"
    else
        printf "%b\n" "${Error} GOST 启动失败，查看日志: $LOG_FILE"
    fi
}

stop_gost() {
    if [ -f "$PID_FILE" ]; then
        pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            rm -f "$PID_FILE"
            printf "%b\n" "${Info} GOST 已停止"
        else
            rm -f "$PID_FILE"
            printf "%b\n" "${Warning} GOST 未在运行"
        fi
    else
        pkill -f "$GOST_BIN" 2>/dev/null
        printf "%b\n" "${Info} GOST 已停止"
    fi
}

restart_gost() {
    stop_gost
    sleep 1
    start_gost
}

status_gost() {
    if [ -f "$PID_FILE" ]; then
        pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            printf "%b\n" "${Green}运行中${Reset} (PID: $pid)"
            return 0
        fi
    fi
    printf "%b\n" "${Red}已停止${Reset}"
    return 1
}

# ==================== 日志管理 ====================
show_log_menu() {
    printf "\n"
    printf "%b\n" "${Green}========== 日志管理 ==========${Reset}"
    printf "[1] 查看最新日志 (50行)\n"
    printf "[2] 查看全部日志\n"
    printf "[3] 实时查看日志 (Ctrl+C 退出)\n"
    printf "[4] 清空日志\n"
    printf "[0] 返回\n"
    printf "%b\n" "${Green}==============================${Reset}"
    printf "请选择 [0-4]: "
    read log_choice
    
    case "$log_choice" in
        1)
            if [ -f "$LOG_FILE" ]; then
                printf "\n"
                printf "%b\n" "${Cyan}========== 最新 50 行日志 ==========${Reset}"
                tail -50 "$LOG_FILE"
                printf "%b\n" "${Cyan}=================================${Reset}"
            else
                printf "%b\n" "${Warning} 日志文件不存在"
            fi
            ;;
        2)
            if [ -f "$LOG_FILE" ]; then
                printf "\n"
                printf "%b\n" "${Cyan}========== 全部日志 ==========${Reset}"
                cat "$LOG_FILE"
                printf "%b\n" "${Cyan}============================${Reset}"
            else
                printf "%b\n" "${Warning} 日志文件不存在"
            fi
            ;;
        3)
            if [ -f "$LOG_FILE" ]; then
                printf "\n"
                printf "%b\n" "${Info} 实时查看日志，按 Ctrl+C 退出..."
                tail -f "$LOG_FILE"
            else
                printf "%b\n" "${Warning} 日志文件不存在"
            fi
            ;;
        4)
            if [ -f "$LOG_FILE" ]; then
                printf "确定要清空日志吗? [y/N]: "
                read confirm
                case "$confirm" in
                    [Yy]*)
                        cat /dev/null > "$LOG_FILE"
                        printf "%b\n" "${Info} 日志已清空"
                        ;;
                esac
            else
                printf "%b\n" "${Warning} 日志文件不存在"
            fi
            ;;
        0|"")
            return
            ;;
        *)
            printf "%b\n" "${Error} 无效选择"
            ;;
    esac
}

# ==================== 添加中转 ====================
add_relay_config() {
    printf "\n"
    printf "%b\n" "${Info} 请选择配置方式:"
    printf "[1] 粘贴节点链接 (自动解析)\n"
    printf "[2] 手动输入目标地址\n"
    printf "请选择 [默认1]: "
    read input_type
    input_type=${input_type:-1}
    
    proto="" parsed="" port_type="tcp"
    
    if [ "$input_type" = "1" ]; then
        printf "请粘贴节点链接: "
        read node_link
        
        if [ -z "$node_link" ]; then
            printf "%b\n" "${Error} 链接不能为空"
            return 1
        fi
        
        proto=$(detect_protocol "$node_link")
        if [ "$proto" = "unknown" ]; then
            printf "%b\n" "${Error} 无法识别的协议"
            return 1
        fi
        
        printf "%b\n" "${Info} 协议: ${Green}${proto}${Reset}"
        
        if ! check_unsupported_protocol "$node_link" "$proto"; then
            printf "是否仍要继续? [y/N]: "
            read force_continue
            case "$force_continue" in
                [Yy]*) ;;
                *) return 1 ;;
            esac
        fi
        
        port_type=$(detect_protocol_type "$proto")
        printf "%b\n" "${Info} 端口类型: ${Green}${port_type}${Reset}"
        
        parsed=$(parse_node "$node_link")
        target=$(get_target "$proto" "$parsed")
        target_host=$(echo "$target" | cut -d'|' -f1)
        target_port=$(echo "$target" | cut -d'|' -f2)
        
        printf "%b\n" "${Info} 目标: ${Green}${target_host}:${target_port}${Reset}"
        
        if ! check_port_connectivity "$target_host" "$target_port" 3; then
            printf "%b\n" "${Warning} 目标端口不可达"
            printf "是否仍要添加? [y/N]: "
            read confirm
            case "$confirm" in
                [Yy]*) ;;
                *) return 1 ;;
            esac
        fi
    else
        printf "目标地址: "
        read target_host
        printf "目标端口: "
        read target_port
    fi
    
    # 端口配置
    printf "\n"
    printf "%b\n" "${Info} 端口配置 (类型: ${port_type}):"
    
    # 检测 MrChrootBSD 环境，读取已添加的 devil 端口
    DEVIL_PORTS_FILE="/root/.devil_ports"
    devil_ports=""
    
    if [ "$IS_MRCHROOT" = "true" ] && [ -f "$DEVIL_PORTS_FILE" ] && [ -s "$DEVIL_PORTS_FILE" ]; then
        printf "%b\n" "${Yellow}========================================${Reset}"
        printf "%b\n" "${Warning} 检测到 MrChrootBSD 环境!"
        printf "%b\n" "${Tip} 请使用已通过 devil 添加的端口"
        printf "%b\n" "${Yellow}========================================${Reset}"
        printf "\n"
        printf "%b\n" "${Info} 已添加的 devil 端口:"
        i=1
        while read port; do
            printf "  [%d] %s\n" "$i" "$port"
            devil_ports="${devil_ports}${port} "
            i=$((i + 1))
        done < "$DEVIL_PORTS_FILE"
        printf "\n"
        printf "[1] 选择已添加的 devil 端口 (推荐)\n"
        printf "[2] 手动输入端口\n"
        printf "请选择 [默认1]: "
        read port_mode
        port_mode=${port_mode:-1}
        
        case $port_mode in
            1)
                printf "请输入端口序号: "
                read port_index
                if [ -z "$port_index" ]; then
                    port_index=1
                fi
                local_port=$(echo "$devil_ports" | cut -d' ' -f"$port_index")
                if [ -z "$local_port" ]; then
                    printf "%b\n" "${Error} 无效序号"
                    return 1
                fi
                printf "%b\n" "${Info} 选择端口: ${Green}$local_port (${port_type})${Reset}"
                ;;
            2)
                printf "请输入端口 (确保已通过 devil 添加): "
                read local_port
                ;;
            *)
                printf "%b\n" "${Error} 无效选择"
                return 1
                ;;
        esac
    elif [ "$IS_MRCHROOT" = "true" ]; then
        printf "%b\n" "${Yellow}========================================${Reset}"
        printf "%b\n" "${Warning} 检测到 MrChrootBSD 环境!"
        printf "%b\n" "${Red}未找到已添加的 devil 端口!${Reset}"
        printf "%b\n" "${Yellow}========================================${Reset}"
        printf "\n"
        printf "%b\n" "${Tip} 请先退出 chroot，在宿主环境中添加端口:"
        printf "%b\n" "   1. 退出 chroot: exit"
        printf "%b\n" "   2. 运行: ./setup.sh"
        printf "%b\n" "   3. 选择 11 - Devil 端口管理"
        printf "%b\n" "   4. 添加端口后重新进入 chroot"
        printf "\n"
        printf "是否仍要继续? (端口可能无法绑定) [y/N]: "
        read force_continue
        case "$force_continue" in
            [Yy]*)
                printf "请输入端口号: "
                read local_port
                ;;
            *)
                return 1
                ;;
        esac
    else
        # 非 MrChrootBSD 环境，正常选择端口
        printf "[1] 随机端口\n"
        printf "[2] 手动指定端口\n"
        printf "请选择 [默认1]: "
        read port_mode
        port_mode=${port_mode:-1}
        
        case $port_mode in
            1)
                local_port=$(get_random_port 10000 65535)
                retry=0
                while ! check_port "$local_port" && [ "$retry" -lt 20 ]; do
                    local_port=$(get_random_port 10000 65535)
                    retry=$((retry + 1))
                done
                printf "%b\n" "${Info} 分配端口: ${Green}$local_port (${port_type})${Reset}"
                ;;
            2)
                printf "请输入端口: "
                read local_port
                if ! check_port "$local_port"; then
                    printf "%b\n" "${Warning} 端口可能已被占用"
                fi
                ;;
            *)
                printf "%b\n" "${Error} 无效选择"
                return 1
                ;;
        esac
    fi
    
    echo "$local_port" >> "$PORT_CONF"
    
    # 获取本机IP
    my_ip=$(curl -s4m5 ip.sb 2>/dev/null) || my_ip=$(curl -s4m5 ifconfig.me 2>/dev/null)
    [ -z "$my_ip" ] && my_ip="YOUR_IP"
    
    add_relay "$local_port" "$target_host" "$target_port" "$port_type"
    restart_gost
    
    printf "\n"
    printf "%b\n" "${Green}===========================================${Reset}"
    printf "%b\n" "${Info} 中转配置完成!"
    printf "%b\n" "${Green}===========================================${Reset}"
    printf " 本机IP:    ${Cyan}${my_ip}${Reset}\n"
    printf " 本地端口:  ${Cyan}${local_port} (${port_type})${Reset}\n"
    printf " 目标地址:  ${target_host}:${target_port}\n"
    printf "%b\n" "${Green}===========================================${Reset}"
    
    if [ "$input_type" = "1" ] && [ -n "$parsed" ]; then
        relay_link=$(generate_relay_link "$proto" "$parsed" "$my_ip" "$local_port")
        printf "\n"
        printf "%b\n" "${Info} 中转后的链接:"
        printf "%b\n" "${Cyan}${relay_link}${Reset}"
    fi
}

# ==================== 查看配置 ====================
show_config() {
    printf "\n"
    printf "%b\n" "${Green}==================== 当前配置 ====================${Reset}"
    
    if [ ! -f "$RAW_CONF" ] || [ ! -s "$RAW_CONF" ]; then
        printf "%b\n" "${Warning} 暂无配置"
        return
    fi
    
    printf "%-4s | %-8s | %s\n" "序号" "本地端口" "目标地址"
    printf "----------------------------------------\n"
    
    i=1
    while IFS='|' read -r type proto port host dport; do
        printf "%-4s | %-8s | %s\n" "$i" "$port" "$host:$dport"
        i=$((i + 1))
    done < "$RAW_CONF"
    
    printf "%b\n" "${Green}==================================================${Reset}"
}

# ==================== 删除配置 ====================
delete_config() {
    show_config
    
    if [ ! -s "$RAW_CONF" ]; then
        return
    fi
    
    printf "删除序号 (0取消): "
    read num
    [ "$num" = "0" ] && return
    
    case "$num" in
        *[!0-9]*)
            printf "%b\n" "${Error} 无效输入"
            return
            ;;
    esac
    
    total=$(wc -l < "$RAW_CONF")
    if [ "$num" -lt 1 ] || [ "$num" -gt "$total" ]; then
        printf "%b\n" "${Error} 序号超出范围"
        return
    fi
    
    # 删除指定行
    sed -i.bak "${num}d" "$RAW_CONF" 2>/dev/null || sed "${num}d" "$RAW_CONF" > "$RAW_CONF.tmp" && mv "$RAW_CONF.tmp" "$RAW_CONF"
    
    # 重新生成 GOST 配置
    cat > "$GOST_CONF" << 'EOF'
services: []
EOF
    
    while IFS='|' read -r type proto port host dport; do
        [ -z "$port" ] && continue
        config=$(generate_gost_config "$port" "$host" "$dport" "$proto")
        if grep -q "^services: \[\]$" "$GOST_CONF" 2>/dev/null; then
            cat > "$GOST_CONF" << EOF
services:
${config}
EOF
        else
            echo "$config" >> "$GOST_CONF"
        fi
    done < "$RAW_CONF"
    
    restart_gost
    printf "%b\n" "${Info} 配置已删除"
}

# ==================== 卸载 ====================
uninstall_gost() {
    printf "%b\n" "${Warning} 确定要卸载 GOST？[y/N]: "
    read confirm
    case "$confirm" in
        [Yy]*)
            stop_gost
            rm -rf "$GOST_DIR"
            rm -f "$SCRIPT_PATH" 2>/dev/null
            rm -f "$HOME/bin/gostxray" 2>/dev/null
            printf "%b\n" "${Info} GOST 已卸载"
            ;;
        *)
            printf "%b\n" "${Info} 已取消"
            ;;
    esac
}

# ==================== 状态显示 ====================
show_status() {
    printf "\n"
    printf "%b\n" "${Green}==================== 状态 ====================${Reset}"
    
    printf " GOST v3:   "
    if [ -f "$GOST_BIN" ]; then
        status_gost
    else
        printf "%b\n" "${Yellow}未安装${Reset}"
    fi
    
    if [ -f "$RAW_CONF" ] && [ -s "$RAW_CONF" ]; then
        count=$(wc -l < "$RAW_CONF")
        printf " 中转配置: %s 条\n" "$count"
    else
        printf " 中转配置: 0 条\n"
    fi
    
    my_ip=$(curl -s4m5 ip.sb 2>/dev/null) || my_ip="获取中..."
    printf " 本机 IP:   %s\n" "$my_ip"
    
    printf "%b\n" "${Green}================================================${Reset}"
}

# ==================== 主菜单 ====================
show_menu() {
    clear
    show_status
    
    printf "
${Green}========================================================${Reset}
      GOST v3 中转管理脚本 ${Red}[${shell_version}]${Reset}
${Green}========================================================${Reset}
 ${Cyan}支持: VLESS VMess Trojan SS Hy2 TUIC SOCKS HTTP${Reset}
${Green}--------------------------------------------------------${Reset}
 ${Green}1.${Reset}  安装 GOST v3          ${Green}2.${Reset}  卸载 GOST v3
${Green}--------------------------------------------------------${Reset}
 ${Green}3.${Reset}  启动 GOST v3          ${Green}4.${Reset}  停止 GOST v3
 ${Green}5.${Reset}  重启 GOST v3          ${Green}6.${Reset}  查看日志
${Green}--------------------------------------------------------${Reset}
 ${Green}7.${Reset}  添加中转配置          ${Green}8.${Reset}  查看当前配置
 ${Green}9.${Reset}  删除配置
${Green}--------------------------------------------------------${Reset}
 ${Green}10.${Reset} 安装快捷命令
${Green}--------------------------------------------------------${Reset}
 ${Green}0.${Reset}  退出脚本
${Green}========================================================${Reset}
"
    printf " 请选择 [0-10]: "
    read num
    
    case "$num" in
        1) install_gost ;;
        2) uninstall_gost ;;
        3) start_gost ;;
        4) stop_gost ;;
        5) restart_gost ;;
        6) show_log_menu ;;
        7) add_relay_config ;;
        8) show_config ;;
        9) delete_config ;;
        10) install_shortcut ;;
        0) exit 0 ;;
        *) printf "%b\n" "${Error} 无效选择" ;;
    esac
    
    printf "\n"
    printf "按回车继续..."
    read dummy
}

# ==================== 主程序 ====================
main() {
    detect_environment
    check_system
    
    while true; do
        show_menu
    done
}

main
