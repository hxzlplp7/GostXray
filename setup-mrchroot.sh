#!/bin/bash
# MrChrootBSD 一键安装脚本 + GostXray/X-UI 集成
# 适用于 Serv00/Hostuno FreeBSD 非 root 环境
# 通过 MrChrootBSD 获取伪 root 权限，在 chroot 环境中运行服务

Green="\033[32m" && Red="\033[31m" && Yellow="\033[33m"
Cyan="\033[36m" && Reset="\033[0m"
Info="${Green}[信息]${Reset}"
Error="${Red}[错误]${Reset}"
Warning="${Yellow}[警告]${Reset}"
Tip="${Cyan}[提示]${Reset}"

shell_version="1.0.0"

# 用户目录
USER_HOME="$HOME"
MRCHROOT_DIR="$USER_HOME/.mrchroot"
CHROOT_DIR="$MRCHROOT_DIR/chroot"
MRCHROOT_BIN="$MRCHROOT_DIR/mrchroot"
FREEBSD_VERSION="15.0-RELEASE"

# ==================== 系统检测 ====================
check_system() {
    local os=$(uname -s)
    local arch=$(uname -m)
    
    if [[ "$os" != "FreeBSD" ]]; then
        echo -e "${Error} 此脚本仅支持 FreeBSD 系统 (Serv00/Hostuno)"
        echo -e "${Warning} 当前系统: $os"
        exit 1
    fi
    
    case $arch in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        i386|i686) ARCH="i386" ;;
        *) echo -e "${Error} 不支持的架构: $arch"; exit 1 ;;
    esac
    
    echo -e "${Info} 系统: $os ($arch)"
}

# ==================== 依赖检查 ====================
check_dependencies() {
    echo -e "${Info} 检查依赖..."
    
    local missing=""
    
    # 检查必要工具
    for cmd in cmake make gcc wget tar; do
        if ! command -v $cmd &>/dev/null; then
            missing="$missing $cmd"
        fi
    done
    
    if [ -n "$missing" ]; then
        echo -e "${Warning} 缺少依赖:$missing"
        echo -e "${Tip} 请联系 Serv00/Hostuno 管理员安装这些工具"
        echo -e "${Tip} 或尝试: pkg install$missing"
        return 1
    fi
    
    echo -e "${Info} 依赖检查通过"
    return 0
}

# ==================== 下载 MrChrootBSD ====================
download_mrchroot() {
    echo -e "${Info} 下载 MrChrootBSD..."
    
    mkdir -p "$MRCHROOT_DIR"
    cd "$MRCHROOT_DIR"
    
    # 从 GitHub 下载
    local github_url="https://github.com/nrootconauto/MrChrootBSD/archive/refs/heads/master.tar.gz"
    
    if command -v curl &>/dev/null; then
        curl -sL "$github_url" -o mrchroot.tar.gz
    elif command -v wget &>/dev/null; then
        wget -q "$github_url" -O mrchroot.tar.gz
    elif command -v fetch &>/dev/null; then
        fetch -q "$github_url" -o mrchroot.tar.gz
    else
        echo -e "${Error} 无法下载，请安装 curl, wget 或 fetch"
        return 1
    fi
    
    tar -xzf mrchroot.tar.gz
    mv MrChrootBSD-master/* .
    rm -rf MrChrootBSD-master mrchroot.tar.gz
    
    echo -e "${Info} MrChrootBSD 下载完成"
}

# ==================== 编译 MrChrootBSD ====================
compile_mrchroot() {
    echo -e "${Info} 编译 MrChrootBSD..."
    
    cd "$MRCHROOT_DIR"
    
    # 使用 cmake 编译
    cmake . 2>&1 | head -20
    if [ $? -ne 0 ]; then
        echo -e "${Error} cmake 配置失败"
        return 1
    fi
    
    make 2>&1 | head -30
    if [ $? -ne 0 ]; then
        echo -e "${Error} 编译失败"
        return 1
    fi
    
    if [ -f "mrchroot" ]; then
        chmod +x mrchroot
        echo -e "${Info} MrChrootBSD 编译成功"
        return 0
    else
        echo -e "${Error} 编译后未找到 mrchroot 二进制文件"
        return 1
    fi
}

# ==================== 获取文件大小 (兼容 FreeBSD 和 Linux) ====================
get_file_size() {
    local file="$1"
    local size=0
    
    if [ -f "$file" ]; then
        # FreeBSD: stat -f %z
        # Linux: stat -c %s
        # 或者使用 wc -c
        size=$(stat -f '%z' "$file" 2>/dev/null) || \
        size=$(stat -c '%s' "$file" 2>/dev/null) || \
        size=$(wc -c < "$file" 2>/dev/null | tr -d ' ') || \
        size=$(ls -l "$file" 2>/dev/null | awk '{print $5}') || \
        size=0
    fi
    
    echo "$size"
}

# ==================== 下载 FreeBSD Base ====================
download_freebsd_base() {
    echo -e "${Info} 下载 FreeBSD $FREEBSD_VERSION base 系统..."
    
    cd "$MRCHROOT_DIR"
    
    local base_url="https://download.freebsd.org/releases/${ARCH}/${FREEBSD_VERSION}/base.txz"
    local lib32_url="https://download.freebsd.org/releases/${ARCH}/${FREEBSD_VERSION}/lib32.txz"
    
    # 下载 base.txz
    if [ ! -f "base.txz" ]; then
        echo -e "${Info} 下载 base.txz (约 180MB，请耐心等待)..."
        
        # 优先使用 wget (更可靠)
        if command -v wget &>/dev/null; then
            wget "$base_url"
        elif command -v fetch &>/dev/null; then
            fetch "$base_url"
        elif command -v curl &>/dev/null; then
            curl -L -O "$base_url"
        else
            echo -e "${Error} 没有可用的下载工具 (wget/fetch/curl)"
            return 1
        fi
        
        if [ ! -f "base.txz" ]; then
            echo -e "${Error} base.txz 下载失败"
            return 1
        fi
        echo -e "${Info} base.txz 下载完成"
    else
        echo -e "${Info} base.txz 已存在，跳过下载"
    fi
    
    # 下载 lib32.txz (可选，用于 gdb 等)
    if [ "$ARCH" = "amd64" ] && [ ! -f "lib32.txz" ]; then
        echo -e "${Info} 下载 lib32.txz (可选)..."
        if command -v wget &>/dev/null; then
            wget "$lib32_url" 2>/dev/null || true
        elif command -v fetch &>/dev/null; then
            fetch "$lib32_url" 2>/dev/null || true
        fi
    fi
    
    echo -e "${Info} FreeBSD base 下载完成"
}

# ==================== 设置 chroot 环境 ====================
# 参考 serv00-play 项目的实现方式
setup_chroot() {
    echo -e "${Info} 设置 chroot 环境..."
    
    cd "$MRCHROOT_DIR"
    
    # 检查 base.txz 是否存在
    if [ ! -f "base.txz" ]; then
        echo -e "${Error} base.txz 不存在，请先下载"
        return 1
    fi
    
    # 创建 chroot 目录
    mkdir -p "$CHROOT_DIR"
    
    # 直接使用 tar 解压 base.txz 到 chroot 目录 (关键步骤!)
    echo -e "${Info} 解压 base.txz 到 chroot 环境 (这可能需要几分钟)..."
    cd "$CHROOT_DIR"
    tar xvf ../base.txz
    
    if [ $? -ne 0 ]; then
        echo -e "${Error} base.txz 解压失败"
        return 1
    fi
    
    # 验证解压结果
    if [ ! -d "$CHROOT_DIR/bin" ] || [ ! -d "$CHROOT_DIR/usr" ]; then
        echo -e "${Error} chroot 环境不完整"
        return 1
    fi
    
    echo -e "${Info} base.txz 解压成功"
    
    # 解压 lib32.txz (如果存在)
    if [ -f "../lib32.txz" ]; then
        echo -e "${Info} 解压 lib32.txz..."
        tar xvf ../lib32.txz || echo -e "${Warning} lib32.txz 解压失败，跳过"
    fi
    
    cd "$MRCHROOT_DIR"
    
    # 复制 resolv.conf 用于网络
    if [ -f /etc/resolv.conf ] && [ -d "$CHROOT_DIR/etc" ]; then
        cp /etc/resolv.conf "$CHROOT_DIR/etc/"
        echo -e "${Info} 已复制 resolv.conf"
    fi
    
    # 创建必要的目录
    mkdir -p "$CHROOT_DIR/root"
    mkdir -p "$CHROOT_DIR/tmp"
    
    # 创建环境标记文件
    touch "$CHROOT_DIR/root/.mrchroot_env"
    
    echo -e "${Info} chroot 环境设置完成"
    echo -e "${Info} chroot 目录: $CHROOT_DIR"
    
    # 尝试在 chroot 中安装 bash (脚本需要 bash)
    echo -e "${Info} 正在安装 bash..."
    cd "$MRCHROOT_DIR"
    if ./mrchroot "$CHROOT_DIR" pkg install -y bash 2>/dev/null; then
        echo -e "${Info} bash 安装成功"
    else
        echo -e "${Warning} bash 安装失败，可能需要手动安装"
        echo -e "${Tip} 进入 chroot 后运行: pkg install bash"
    fi
}

# ==================== 安装 GostXray 到 chroot ====================
install_gostxray_to_chroot() {
    echo -e "${Info} 安装 GostXray 到 chroot 环境..."
    
    # 下载 gost-root.sh
    local gost_url="https://raw.githubusercontent.com/hxzlplp7/GostXray/main/gost-root.sh"
    
    # 或从本地复制
    if [ -f "$USER_HOME/gostxray/gost-root.sh" ]; then
        cp "$USER_HOME/gostxray/gost-root.sh" "$CHROOT_DIR/root/gost-root.sh"
    else
        # 尝试从 GitHub 下载
        curl -sL "https://raw.githubusercontent.com/hxzlplp7/GostXray/main/gost-root.sh" -o "$CHROOT_DIR/root/gost-root.sh" 2>/dev/null || \
        curl -sL "https://raw.githubusercontent.com/hxzlplp7/GostXray/main/gost-serv00.sh" -o "$CHROOT_DIR/root/gost-root.sh" 2>/dev/null || true
    fi
    
    if [ -f "$CHROOT_DIR/root/gost-root.sh" ]; then
        chmod +x "$CHROOT_DIR/root/gost-root.sh"
        echo -e "${Info} GostXray 脚本已安装到 chroot 环境"
    else
        echo -e "${Warning} GostXray 脚本安装失败，您可以稍后手动安装"
    fi
}

# ==================== 安装 X-UI 到 chroot ====================
install_xui_to_chroot() {
    echo -e "${Info} 安装 X-UI 安装脚本到 chroot 环境..."
    
    # 从本地复制
    if [ -f "$USER_HOME/serv00-xui/x-ui-install-root.sh" ]; then
        cp "$USER_HOME/serv00-xui/x-ui-install-root.sh" "$CHROOT_DIR/root/x-ui-install.sh"
    else
        # 尝试从 GitHub 下载
        curl -sL "https://raw.githubusercontent.com/hxzlplp7/serv00-xui/main/x-ui-install-root.sh" -o "$CHROOT_DIR/root/x-ui-install.sh" 2>/dev/null || \
        curl -sL "https://raw.githubusercontent.com/hxzlplp7/serv00-xui/main/x-ui-install.sh" -o "$CHROOT_DIR/root/x-ui-install.sh" 2>/dev/null || true
    fi
    
    if [ -f "$CHROOT_DIR/root/x-ui-install.sh" ]; then
        chmod +x "$CHROOT_DIR/root/x-ui-install.sh"
        echo -e "${Info} X-UI 安装脚本已安装到 chroot 环境"
    else
        echo -e "${Warning} X-UI 安装脚本安装失败，您可以稍后手动安装"
    fi
}

# ==================== 创建快捷命令 ====================
create_shortcuts() {
    echo -e "${Info} 创建快捷命令..."
    
    mkdir -p "$USER_HOME/bin"
    
    # 创建进入 chroot 环境的快捷命令
    cat > "$USER_HOME/bin/mrchroot" << EOF
#!/bin/bash
# 进入 MrChrootBSD chroot 环境
cd "$MRCHROOT_DIR"
./mrchroot "$CHROOT_DIR" /bin/sh
EOF
    chmod +x "$USER_HOME/bin/mrchroot"
    
    # 创建在 chroot 中执行命令的快捷命令
    cat > "$USER_HOME/bin/mrexec" << 'EOF'
#!/bin/bash
# 在 MrChrootBSD chroot 环境中执行命令
MRCHROOT_DIR="$HOME/.mrchroot"
CHROOT_DIR="$MRCHROOT_DIR/chroot"

if [ $# -eq 0 ]; then
    echo "用法: mrexec <命令>"
    echo "示例: mrexec gostxray"
    exit 1
fi

cd "$MRCHROOT_DIR"
./mrchroot "$CHROOT_DIR" "$@"
EOF
    chmod +x "$USER_HOME/bin/mrexec"
    
    # 创建在 chroot 中运行 gostxray 的快捷命令
    cat > "$USER_HOME/bin/gostxray-root" << 'EOF'
#!/bin/sh
# 在 MrChrootBSD root 环境中运行 GostXray
MRCHROOT_DIR="$HOME/.mrchroot"
CHROOT_DIR="$MRCHROOT_DIR/chroot"

cd "$MRCHROOT_DIR"
./mrchroot "$CHROOT_DIR" /usr/local/bin/bash /root/gost-root.sh
EOF
    chmod +x "$USER_HOME/bin/gostxray-root"
    
    # 创建在 chroot 中安装 x-ui 的快捷命令
    cat > "$USER_HOME/bin/xui-root" << 'EOF'
#!/bin/sh
# 在 MrChrootBSD root 环境中安装/管理 X-UI
MRCHROOT_DIR="$HOME/.mrchroot"
CHROOT_DIR="$MRCHROOT_DIR/chroot"

cd "$MRCHROOT_DIR"

if [ "$1" = "install" ]; then
    ./mrchroot "$CHROOT_DIR" /usr/local/bin/bash /root/x-ui-install.sh
elif [ "$1" = "menu" ] || [ -z "$1" ]; then
    ./mrchroot "$CHROOT_DIR" /usr/local/bin/bash /root/x-ui.sh
else
    ./mrchroot "$CHROOT_DIR" /usr/local/bin/bash /root/x-ui.sh "$@"
fi
EOF
    chmod +x "$USER_HOME/bin/xui-root"
    
    # 添加到 PATH
    if ! grep -q 'HOME/bin' "$USER_HOME/.profile" 2>/dev/null; then
        echo 'export PATH="$HOME/bin:$PATH"' >> "$USER_HOME/.profile"
    fi
    
    echo -e "${Info} 快捷命令创建完成"
}

# ==================== 显示使用说明 ====================
show_usage() {
    echo -e ""
    echo -e "${Green}╔══════════════════════════════════════════════════════════════╗${Reset}"
    echo -e "${Green}║           MrChrootBSD + GostXray/X-UI 安装完成               ║${Reset}"
    echo -e "${Green}╚══════════════════════════════════════════════════════════════╝${Reset}"
    echo -e ""
    echo -e "${Cyan}快捷命令使用方法:${Reset}"
    echo -e "--------------------------------------------------------------"
    echo -e " ${Green}mrchroot${Reset}       - 进入 chroot root 环境 (shell)"
    echo -e " ${Green}mrexec <cmd>${Reset}   - 在 chroot 中执行命令"
    echo -e " ${Green}gostxray-root${Reset}  - 运行 GostXray (root 版本)"
    echo -e " ${Green}xui-root install${Reset} - 安装 X-UI (root 版本)"
    echo -e " ${Green}xui-root${Reset}       - 运行 X-UI 管理菜单"
    echo -e "--------------------------------------------------------------"
    echo -e ""
    echo -e "${Yellow}重要提示:${Reset}"
    echo -e " 1. 请先执行 ${Green}source ~/.profile${Reset} 使快捷命令生效"
    echo -e " 2. 首次使用建议先进入 chroot: ${Green}mrchroot${Reset}"
    echo -e " 3. 在 chroot 中可以使用 pkg 安装软件"
    echo -e " 4. 退出 chroot 使用 ${Green}exit${Reset} 命令"
    echo -e ""
    echo -e "${Cyan}示例操作:${Reset}"
    echo -e " # 进入 chroot 环境并安装软件"
    echo -e " mrchroot"
    echo -e " pkg update && pkg install curl wget"
    echo -e " exit"
    echo -e ""
    echo -e " # 在 chroot 中安装并运行 GostXray"
    echo -e " gostxray-root"
    echo -e ""
    echo -e " # 在 chroot 中安装 X-UI"
    echo -e " xui-root install"
    echo -e ""
    echo -e "${Green}======================================================${Reset}"
}

# ==================== 卸载 ====================
uninstall() {
    echo -e "${Warning} 确定要卸载 MrChrootBSD 及相关组件? [y/N]"
    read -p "" confirm
    [[ ! $confirm =~ ^[Yy]$ ]] && return
    
    echo -e "${Info} 正在卸载..."
    
    # 删除 chroot 目录
    if [ -d "$MRCHROOT_DIR" ]; then
        rm -rf "$MRCHROOT_DIR"
        echo -e "${Info} 已删除 $MRCHROOT_DIR"
    fi
    
    # 删除快捷命令
    rm -f "$USER_HOME/bin/mrchroot"
    rm -f "$USER_HOME/bin/mrexec"
    rm -f "$USER_HOME/bin/gostxray-root"
    rm -f "$USER_HOME/bin/xui-root"
    
    echo -e "${Info} 卸载完成"
}

# ==================== 显示状态 ====================
show_status() {
    echo -e ""
    echo -e "${Green}==================== 状态 ====================${Reset}"
    
    if [ -f "$MRCHROOT_BIN" ]; then
        echo -e " MrChrootBSD: ${Green}已安装${Reset}"
    else
        echo -e " MrChrootBSD: ${Red}未安装${Reset}"
    fi
    
    if [ -d "$CHROOT_DIR" ]; then
        local size=$(du -sh "$CHROOT_DIR" 2>/dev/null | cut -f1)
        echo -e " Chroot环境:  ${Green}已配置${Reset} (${size})"
    else
        echo -e " Chroot环境:  ${Red}未配置${Reset}"
    fi
    
    if [ -f "$CHROOT_DIR/root/gost-root.sh" ]; then
        echo -e " GostXray:    ${Green}已安装${Reset}"
    else
        echo -e " GostXray:    ${Yellow}未安装${Reset}"
    fi
    
    if [ -f "$CHROOT_DIR/root/x-ui-install.sh" ]; then
        echo -e " X-UI:        ${Green}脚本已就绪${Reset}"
    else
        echo -e " X-UI:        ${Yellow}脚本未就绪${Reset}"
    fi
    
    echo -e "${Green}================================================${Reset}"
}

# ==================== 主菜单 ====================
show_menu() {
    clear
    show_status
    
    echo -e "
${Green}========================================================${Reset}
   MrChrootBSD 一键安装脚本 ${Red}[${shell_version}]${Reset}
${Green}========================================================${Reset}
 ${Cyan}在 Serv00/Hostuno 上获取伪 root 权限${Reset}
${Green}--------------------------------------------------------${Reset}
 ${Green}1.${Reset}  一键安装 MrChrootBSD + 配置环境
 ${Green}2.${Reset}  仅下载/编译 MrChrootBSD
 ${Green}3.${Reset}  仅下载 FreeBSD base
 ${Green}4.${Reset}  仅设置 chroot 环境
${Green}--------------------------------------------------------${Reset}
 ${Green}5.${Reset}  进入 chroot 环境
 ${Green}6.${Reset}  在 chroot 中运行 GostXray
 ${Green}7.${Reset}  在 chroot 中安装 X-UI
${Green}--------------------------------------------------------${Reset}
 ${Green}8.${Reset}  安装 GostXray 脚本到 chroot
 ${Green}9.${Reset}  安装 X-UI 脚本到 chroot
${Green}--------------------------------------------------------${Reset}
 ${Green}10.${Reset} 卸载
 ${Green}0.${Reset}  退出
${Green}========================================================${Reset}
"
    read -p " 请选择 [0-10]: " num
    
    case "$num" in
        1)
            # 一键安装
            check_system
            if ! check_dependencies; then
                echo -e "${Error} 依赖检查失败"
                return
            fi
            download_mrchroot
            compile_mrchroot
            download_freebsd_base
            setup_chroot
            install_gostxray_to_chroot
            install_xui_to_chroot
            create_shortcuts
            show_usage
            ;;
        2)
            check_system
            check_dependencies
            download_mrchroot
            compile_mrchroot
            ;;
        3)
            check_system
            download_freebsd_base
            ;;
        4)
            check_system
            setup_chroot
            create_shortcuts
            ;;
        5)
            if [ -f "$MRCHROOT_BIN" ] && [ -d "$CHROOT_DIR" ]; then
                cd "$MRCHROOT_DIR"
                echo -e "${Info} 正在进入 chroot 环境... (使用 exit 退出)"
                ./mrchroot "$CHROOT_DIR" /bin/sh
            else
                echo -e "${Error} MrChrootBSD 或 chroot 环境未配置"
            fi
            ;;
        6)
            if [ -f "$MRCHROOT_BIN" ] && [ -f "$CHROOT_DIR/root/gost-root.sh" ]; then
                cd "$MRCHROOT_DIR"
                ./mrchroot "$CHROOT_DIR" /usr/local/bin/bash /root/gost-root.sh
            else
                echo -e "${Error} GostXray 未安装到 chroot 环境"
            fi
            ;;
        7)
            if [ -f "$MRCHROOT_BIN" ] && [ -f "$CHROOT_DIR/root/x-ui-install.sh" ]; then
                cd "$MRCHROOT_DIR"
                ./mrchroot "$CHROOT_DIR" /usr/local/bin/bash /root/x-ui-install.sh
            else
                echo -e "${Error} X-UI 安装脚本未安装到 chroot 环境"
            fi
            ;;
        8)
            install_gostxray_to_chroot
            ;;
        9)
            install_xui_to_chroot
            ;;
        10)
            uninstall
            ;;
        0)
            exit 0
            ;;
        *)
            echo -e "${Error} 无效选择"
            ;;
    esac
    
    echo -e ""
    read -p "按回车继续..."
}

# ==================== 主程序 ====================
main() {
    while true; do
        show_menu
    done
}

# 检查是否有参数
case "$1" in
    install)
        check_system
        check_dependencies
        download_mrchroot
        compile_mrchroot
        download_freebsd_base
        setup_chroot
        install_gostxray_to_chroot
        install_xui_to_chroot
        create_shortcuts
        show_usage
        ;;
    uninstall)
        uninstall
        ;;
    *)
        main
        ;;
esac
