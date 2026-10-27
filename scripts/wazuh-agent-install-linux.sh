#!/bin/bash
# ============================================================
# Wazuh Agent 一键安装脚本 (Linux)
# 支持: Ubuntu / Debian / Kali / CentOS / RHEL / Rocky / AlmaLinux / Amazon Linux / Fedora
# Manager: 172.16.113.66
#
# 使用方法:
#   sudo bash install_wazuh_agent.sh [Agent名称]
#   示例: sudo bash install_wazuh_agent.sh web-server-01
#   不指定名称则自动使用主机名
# ============================================================

set -e

# ============ 配置区 ============
WAZUH_MANAGER="172.16.113.66"
WAZUH_VERSION="4.14.7"
AGENT_NAME="${1:-$(hostname)}"
# ================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo ""
echo "=========================================="
echo "  Wazuh Agent 一键安装"
echo "  Manager : ${WAZUH_MANAGER}"
echo "  版本    : ${WAZUH_VERSION}"
echo "  Agent名 : ${AGENT_NAME}"
echo "=========================================="
echo ""

# 检查root权限
if [ "$EUID" -ne 0 ]; then
    log_error "请使用root或sudo运行此脚本"
    exit 1
fi

# 检测操作系统
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="${ID}"
        OS_VERSION="${VERSION_ID}"
        # 处理衍生版
        case "${OS_ID}" in
            ubuntu|debian|kali)
                OS_FAMILY="debian"
                ;;
            centos|rhel|rocky|almalinux|amzn|fedora|ol|virtuozzo)
                OS_FAMILY="rhel"
                ;;
            *)
                # 尝试通过ID_LIKE判断
                if echo "${ID_LIKE:-}" | grep -qi "debian\|ubuntu"; then
                    OS_FAMILY="debian"
                elif echo "${ID_LIKE:-}" | grep -qi "rhel\|centos\|fedora"; then
                    OS_FAMILY="rhel"
                else
                    OS_FAMILY="unknown"
                fi
                ;;
        esac
    else
        OS_FAMILY="unknown"
    fi
    log_info "检测到系统: ${OS_ID} ${OS_VERSION} (${OS_FAMILY}系)"
}

# 检查是否已安装
check_existing() {
    if [ -d /var/ossec ] && [ -f /var/ossec/bin/wazuh-control ]; then
        log_warn "检测到Wazuh Agent已安装"
        CURRENT_VER=$(/var/ossec/bin/wazuh-control info 2>/dev/null | grep WAZUH_VERSION | cut -d'"' -f2)
        log_info "当前版本: ${CURRENT_VER}"
        read -p "是否覆盖重新安装? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "已取消安装"
            exit 0
        fi
        log_info "正在卸载旧版本..."
        if [ "${OS_FAMILY}" = "debian" ]; then
            apt-get remove -y wazuh-agent 2>/dev/null || true
        else
            yum remove -y wazuh-agent 2>/dev/null || dnf remove -y wazuh-agent 2>/dev/null || true
        fi
        rm -rf /var/ossec
    fi
}

# Debian系安装
install_debian() {
    log_info "[1/4] 安装Wazuh GPG密钥..."
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import 2>/dev/null
    chmod 644 /usr/share/keyrings/wazuh.gpg

    log_info "[2/4] 添加Wazuh软件源..."
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list

    log_info "[3/4] 更新软件包列表..."
    apt-get update -qq

    log_info "[4/4] 安装Wazuh Agent..."
    WAZUH_MANAGER="${WAZUH_MANAGER}" apt-get install -y wazuh-agent="${WAZUH_VERSION}-1" 2>/dev/null || \
    WAZUH_MANAGER="${WAZUH_MANAGER}" apt-get install -y wazuh-agent
}

# RHEL系安装
install_rhel() {
    log_info "[1/4] 安装Wazuh GPG密钥..."
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH

    log_info "[2/4] 添加Wazuh软件源..."
    cat > /etc/yum.repos.d/wazuh.repo << 'REPOEOF'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
REPOEOF

    log_info "[3/4] 清理缓存..."
    yum clean all 2>/dev/null || dnf clean all 2>/dev/null || true

    log_info "[4/4] 安装Wazuh Agent..."
    if command -v dnf &> /dev/null; then
        WAZUH_MANAGER="${WAZUH_MANAGER}" dnf install -y wazuh-agent-${WAZUH_VERSION}-1 2>/dev/null || \
        WAZUH_MANAGER="${WAZUH_MANAGER}" dnf install -y wazuh-agent
    else
        WAZUH_MANAGER="${WAZUH_MANAGER}" yum install -y wazuh-agent-${WAZUH_VERSION}-1 2>/dev/null || \
        WAZUH_MANAGER="${WAZUH_MANAGER}" yum install -y wazuh-agent
    fi
}

# 配置Agent
configure_agent() {
    log_info "配置Agent连接Manager..."

    # 确保Manager地址正确
    if grep -q "<address>" /var/ossec/etc/ossec.conf; then
        sed -i "s|<address>.*</address>|<address>${WAZUH_MANAGER}</address>|g" /var/ossec/etc/ossec.conf
    else
        # 在<client>块中插入address
        sed -i "/<client>/a\\    <server>\n      <address>${WAZUH_MANAGER}</address>\n      <port>1514</port>\n      <protocol>tcp</protocol>\n    </server>" /var/ossec/etc/ossec.conf
    fi

    # 设置Agent名称并注册
    log_info "向Manager注册Agent..."
    /var/ossec/bin/agent-auth -m "${WAZUH_MANAGER}" -A "${AGENT_NAME}" 2>/dev/null || \
        log_warn "自动注册失败，将使用主机名自动注册"

    # 启动服务
    log_info "启动Wazuh Agent服务..."
    systemctl daemon-reload
    systemctl enable wazuh-agent
    systemctl start wazuh-agent

    sleep 3
}

# 验证安装
verify_install() {
    echo ""
    echo "=========================================="
    if systemctl is-active --quiet wazuh-agent; then
        log_info "Wazuh Agent 安装成功!"
        echo ""
        echo "  服务状态 : $(systemctl is-active wazuh-agent)"
        echo "  Agent名称: ${AGENT_NAME}"
        echo "  Manager  : ${WAZUH_MANAGER}"
        echo "  版本     : $(/var/ossec/bin/wazuh-control info 2>/dev/null | grep WAZUH_VERSION | cut -d'"' -f2)"
        echo ""
        log_info "在Manager上执行以下命令确认注册:"
        echo "  sudo /var/ossec/bin/agent_control -l"
        echo ""
        log_info "Agent日志查看:"
        echo "  sudo tail -f /var/ossec/logs/ossec.log"
    else
        log_error "Wazuh Agent 启动失败"
        echo "  请检查日志: sudo journalctl -u wazuh-agent -n 50"
        exit 1
    fi
    echo "=========================================="
}

# 主流程
detect_os
check_existing

case "${OS_FAMILY}" in
    debian)
        install_debian
        ;;
    rhel)
        install_rhel
        ;;
    *)
        log_error "不支持的操作系统: ${OS_ID}"
        echo ""
        echo "支持的系统:"
        echo "  Debian系: Ubuntu, Debian, Kali, Linux Mint等"
        echo "  RHEL系  : CentOS, RHEL, Rocky, AlmaLinux, Amazon Linux, Fedora等"
        echo ""
        echo "其他系统请参考官方文档:"
        echo "  https://documentation.wazuh.com/current/installation-guide/wazuh-agent/index.html"
        exit 1
        ;;
esac

configure_agent
verify_install
