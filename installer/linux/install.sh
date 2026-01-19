#!/bin/bash
# ===========================================================================
# Jarwis Agent - Universal Linux Installer
# ===========================================================================
#
# One-liner installation script for Jarwis Security Agent.
# Detects OS and installs appropriate package.
#
# Usage:
#   curl -sL https://jarwis.io/install.sh | sudo bash
#   curl -sL https://jarwis.io/install.sh | sudo bash -s -- YOUR_ACTIVATION_KEY
#
# Supported:
#   - Ubuntu 18.04+, Debian 10+
#   - RHEL/CentOS 7+, Fedora 30+
#   - Amazon Linux 2
#
# ===========================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

ACTIVATION_KEY="${1:-}"
VERSION="1.0.0"
BASE_URL="https://releases.jarwis.io/agent"

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                                                              ║"
echo "║       ██╗ █████╗ ██████╗ ██╗    ██╗██╗███████╗              ║"
echo "║       ██║██╔══██╗██╔══██╗██║    ██║██║██╔════╝              ║"
echo "║       ██║███████║██████╔╝██║ █╗ ██║██║███████╗              ║"
echo "║  ██   ██║██╔══██║██╔══██╗██║███╗██║██║╚════██║              ║"
echo "║  ╚█████╔╝██║  ██║██║  ██║╚███╔███╔╝██║███████║              ║"
echo "║   ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝╚══════╝              ║"
echo "║                                                              ║"
echo "║              Security Testing Agent Installer                ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root (use sudo)${NC}"
    exit 1
fi

# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    elif [ -f /etc/redhat-release ]; then
        OS="rhel"
        OS_VERSION=$(cat /etc/redhat-release | grep -oE '[0-9]+' | head -1)
    else
        echo -e "${RED}Error: Unsupported operating system${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}Detected OS: $OS $OS_VERSION${NC}"
}

# Detect architecture
detect_arch() {
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  ARCH_PKG="amd64" ;;
        aarch64) ARCH_PKG="arm64" ;;
        armv7l)  ARCH_PKG="armhf" ;;
        *)
            echo -e "${RED}Error: Unsupported architecture: $ARCH${NC}"
            exit 1
            ;;
    esac
    
    echo -e "${GREEN}Architecture: $ARCH ($ARCH_PKG)${NC}"
}

# Install on Debian/Ubuntu
install_deb() {
    echo -e "${YELLOW}Installing DEB package...${NC}"
    
    PKG_URL="$BASE_URL/v$VERSION/jarwis-agent_${VERSION}_${ARCH_PKG}.deb"
    TMP_PKG="/tmp/jarwis-agent.deb"
    
    curl -sL "$PKG_URL" -o "$TMP_PKG"
    dpkg -i "$TMP_PKG" || apt-get install -f -y
    rm -f "$TMP_PKG"
}

# Install on RHEL/CentOS/Fedora
install_rpm() {
    echo -e "${YELLOW}Installing RPM package...${NC}"
    
    RPM_ARCH="$ARCH"
    [ "$ARCH" == "amd64" ] && RPM_ARCH="x86_64"
    
    PKG_URL="$BASE_URL/v$VERSION/jarwis-agent-${VERSION}-1.${RPM_ARCH}.rpm"
    TMP_PKG="/tmp/jarwis-agent.rpm"
    
    curl -sL "$PKG_URL" -o "$TMP_PKG"
    
    if command -v dnf &> /dev/null; then
        dnf install -y "$TMP_PKG"
    else
        yum install -y "$TMP_PKG"
    fi
    
    rm -f "$TMP_PKG"
}

# Main installation
main() {
    detect_os
    detect_arch
    
    echo ""
    echo -e "${YELLOW}[1/3] Downloading and installing package...${NC}"
    
    case "$OS" in
        ubuntu|debian|linuxmint|pop)
            install_deb
            ;;
        rhel|centos|fedora|amzn|rocky|almalinux)
            install_rpm
            ;;
        *)
            echo -e "${RED}Error: Unsupported OS: $OS${NC}"
            echo "Supported: Ubuntu, Debian, RHEL, CentOS, Fedora, Amazon Linux"
            exit 1
            ;;
    esac
    
    echo -e "${GREEN}✓ Package installed${NC}"
    
    echo ""
    echo -e "${YELLOW}[2/3] Configuring agent...${NC}"
    
    if [ -n "$ACTIVATION_KEY" ]; then
        echo "Activating with provided key..."
        jarwis-agent --activate "$ACTIVATION_KEY"
        echo -e "${GREEN}✓ Agent activated${NC}"
    else
        echo -e "${YELLOW}⚠ No activation key provided${NC}"
        echo "  Run: sudo jarwis-agent --activate YOUR_KEY"
    fi
    
    echo ""
    echo -e "${YELLOW}[3/3] Starting service...${NC}"
    
    systemctl daemon-reload
    
    if [ -n "$ACTIVATION_KEY" ]; then
        systemctl enable --now jarwis-agent.service
        echo -e "${GREEN}✓ Service started${NC}"
    else
        systemctl enable jarwis-agent.service
        echo -e "${YELLOW}⚠ Service enabled but not started (needs activation)${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║               Installation Complete!                         ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    if [ -n "$ACTIVATION_KEY" ]; then
        echo "Agent is running and connected to Jarwis cloud."
        echo "View in dashboard: https://jarwis.io/agents"
    else
        echo "Next steps:"
        echo "  1. Activate: sudo jarwis-agent --activate YOUR_KEY"
        echo "  2. Start:    sudo systemctl start jarwis-agent"
        echo ""
        echo "Get your activation key at: https://jarwis.io/agent/setup"
    fi
    
    echo ""
    echo "Useful commands:"
    echo "  Status:  sudo systemctl status jarwis-agent"
    echo "  Logs:    sudo journalctl -u jarwis-agent -f"
    echo "  Stop:    sudo systemctl stop jarwis-agent"
    echo "  Remove:  sudo apt remove jarwis-agent  # or yum/dnf"
    echo ""
}

main "$@"
