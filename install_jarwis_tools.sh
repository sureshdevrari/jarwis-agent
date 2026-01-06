#!/bin/bash
# ============================================================================
# JARWIS AGI PEN TEST - Complete Linux Server Installation Script
# ============================================================================
# This script installs ALL dependencies required for Jarwis on Ubuntu/Debian
# 
# Usage: 
#   chmod +x install_jarwis_tools.sh
#   sudo ./install_jarwis_tools.sh
#
# Options:
#   --all         Install everything (default)
#   --minimal     Install only essential tools
#   --network     Install only network security tools
#   --mobile      Install only mobile testing tools
#   --web         Install only web testing tools
#   --skip-mobile Skip mobile tools installation
# ============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[X]${NC} $1"; }
log_section() { echo -e "\n${PURPLE}========================================${NC}"; echo -e "${PURPLE}$1${NC}"; echo -e "${PURPLE}========================================${NC}"; }

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Please run as root: sudo $0"
        exit 1
    fi
}

# Parse command line arguments
INSTALL_MODE="all"
SKIP_MOBILE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --minimal) INSTALL_MODE="minimal"; shift ;;
        --network) INSTALL_MODE="network"; shift ;;
        --mobile) INSTALL_MODE="mobile"; shift ;;
        --web) INSTALL_MODE="web"; shift ;;
        --skip-mobile) SKIP_MOBILE=true; shift ;;
        --all) INSTALL_MODE="all"; shift ;;
        *) shift ;;
    esac
done

# ============================================================================
# SYSTEM UPDATE & PREREQUISITES
# ============================================================================

install_prerequisites() {
    log_section "Installing Prerequisites"
    
    log_info "Updating package manager..."
    apt update && apt upgrade -y
    
    log_info "Installing essential build tools..."
    apt install -y \
        build-essential \
        git \
        curl \
        wget \
        unzip \
        zip \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
        gnupg \
        lsb-release \
        libffi-dev \
        libssl-dev \
        libxml2-dev \
        libxslt1-dev \
        zlib1g-dev \
        libjpeg-dev \
        libpng-dev \
        libpq-dev \
        pkg-config \
        xz-utils
    
    log_success "Prerequisites installed"
}

# ============================================================================
# PYTHON INSTALLATION
# ============================================================================

install_python() {
    log_section "Installing Python 3.11+"
    
    # Add deadsnakes PPA for latest Python
    add-apt-repository -y ppa:deadsnakes/ppa 2>/dev/null || true
    apt update
    
    apt install -y \
        python3.11 \
        python3.11-venv \
        python3.11-dev \
        python3-pip \
        python3-setuptools \
        python3-wheel \
        pipx
    
    # Set python3.11 as default if available
    update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1 2>/dev/null || true
    
    # Upgrade pip
    python3 -m pip install --upgrade pip setuptools wheel
    
    # Install pipx for isolated tool installations
    python3 -m pip install --user pipx
    python3 -m pipx ensurepath
    
    log_success "Python installed: $(python3 --version)"
}

# ============================================================================
# NODE.JS INSTALLATION
# ============================================================================

install_nodejs() {
    log_section "Installing Node.js 20 LTS"
    
    # Install Node.js 20.x LTS
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt install -y nodejs
    
    # Install npm and common global packages
    npm install -g npm@latest
    npm install -g yarn
    
    log_success "Node.js installed: $(node --version)"
    log_success "npm installed: $(npm --version)"
}

# ============================================================================
# GO INSTALLATION
# ============================================================================

install_golang() {
    log_section "Installing Go (Golang)"
    
    GO_VERSION="1.22.0"
    
    if ! command -v go &> /dev/null; then
        wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
        rm -rf /usr/local/go
        tar -C /usr/local -xzf /tmp/go.tar.gz
        rm /tmp/go.tar.gz
    fi
    
    # Set up Go environment
    export GOROOT=/usr/local/go
    export GOPATH=/opt/go
    export PATH=$PATH:$GOROOT/bin:$GOPATH/bin
    
    # Make persistent
    cat > /etc/profile.d/go.sh << 'EOF'
export GOROOT=/usr/local/go
export GOPATH=/opt/go
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin
EOF
    
    mkdir -p $GOPATH
    
    log_success "Go installed: $(go version)"
}

# ============================================================================
# RUST INSTALLATION
# ============================================================================

install_rust() {
    log_section "Installing Rust"
    
    if ! command -v cargo &> /dev/null; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
    fi
    
    export PATH="$HOME/.cargo/bin:$PATH"
    
    log_success "Rust installed: $(rustc --version 2>/dev/null || echo 'installed')"
}

# ============================================================================
# POSTGRESQL DATABASE
# ============================================================================

install_postgresql() {
    log_section "Installing PostgreSQL"
    
    apt install -y postgresql postgresql-contrib
    
    # Start and enable PostgreSQL
    systemctl start postgresql
    systemctl enable postgresql
    
    log_success "PostgreSQL installed and running"
}

# ============================================================================
# NETWORK SECURITY TOOLS
# ============================================================================

install_network_tools() {
    log_section "Installing Network Security Tools"
    
    # Port Scanners
    log_info "Installing port scanners..."
    apt install -y nmap masscan
    
    # Install RustScan
    if ! command -v rustscan &> /dev/null; then
        log_info "Installing RustScan..."
        wget -q https://github.com/RustScan/RustScan/releases/download/2.1.1/rustscan_2.1.1_amd64.deb -O /tmp/rustscan.deb
        dpkg -i /tmp/rustscan.deb || apt install -f -y
        rm /tmp/rustscan.deb
    fi
    
    # Enumeration Tools
    log_info "Installing enumeration tools..."
    apt install -y \
        netdiscover \
        arp-scan \
        snmp \
        snmp-mibs-downloader \
        nbtscan \
        enum4linux \
        dnsutils \
        whois \
        traceroute \
        net-tools
    
    # SSL/TLS Scanners
    log_info "Installing SSL/TLS scanners..."
    apt install -y sslscan
    
    # Install testssl.sh
    if [ ! -d "/opt/testssl" ]; then
        git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl
        ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl.sh
    fi
    
    # Traffic Analysis
    log_info "Installing traffic analysis tools..."
    apt install -y \
        tshark \
        tcpdump \
        wireshark-common \
        ngrep
    
    # Install Suricata
    add-apt-repository -y ppa:oisf/suricata-stable 2>/dev/null || true
    apt update
    apt install -y suricata || log_warn "Suricata install failed"
    
    # Exploitation Tools
    log_info "Installing exploitation tools..."
    apt install -y hydra medusa
    
    log_success "Network security tools installed"
}

# ============================================================================
# GO SECURITY TOOLS (Nuclei, httpx, etc.)
# ============================================================================

install_go_tools() {
    log_section "Installing Go-based Security Tools"
    
    source /etc/profile.d/go.sh 2>/dev/null || true
    export GOPATH=/opt/go
    export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin
    
    GO_TOOLS=(
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        "github.com/projectdiscovery/katana/cmd/katana@latest"
        "github.com/tomnomnom/assetfinder@latest"
        "github.com/ffuf/ffuf/v2@latest"
        "github.com/lc/gau/v2/cmd/gau@latest"
        "github.com/tomnomnom/waybackurls@latest"
    )
    
    for tool in "${GO_TOOLS[@]}"; do
        name=$(echo $tool | rev | cut -d'/' -f1 | rev | cut -d'@' -f1)
        log_info "Installing $name..."
        go install -v "$tool" 2>/dev/null && log_success "$name installed" || log_warn "$name failed"
    done
    
    # Make Go tools available system-wide
    ln -sf /opt/go/bin/* /usr/local/bin/ 2>/dev/null || true
}

# ============================================================================
# PYTHON SECURITY PACKAGES
# ============================================================================

install_python_packages() {
    log_section "Installing Python Security Packages"
    
    # Core packages
    PYTHON_PACKAGES=(
        # Network scanning
        "python-nmap"
        "sslyze"
        "dnspython"
        "pysnmp"
        "scapy"
        
        # Web testing
        "mitmproxy"
        "requests"
        "httpx"
        "aiohttp"
        "beautifulsoup4"
        "lxml"
        "selenium"
        
        # Browser automation
        "playwright"
        
        # Exploitation
        "impacket"
        "pycryptodome"
        
        # Mobile security
        "frida-tools"
        "androguard"
        "objection"
        
        # Reporting
        "reportlab"
        "python-docx"
        "jinja2"
        "sarif-om"
        
        # Cloud SDKs
        "boto3"
        "azure-identity"
        "azure-mgmt-resource"
        "google-cloud-storage"
        
        # Database
        "sqlalchemy[asyncio]"
        "asyncpg"
        "psycopg2-binary"
        "alembic"
        
        # FastAPI
        "fastapi"
        "uvicorn[standard]"
        "python-multipart"
        "python-jose[cryptography]"
        "argon2-cffi"
        
        # Utilities
        "pyyaml"
        "python-dotenv"
        "colorama"
        "rich"
        "tqdm"
        "pydantic"
        "pydantic-settings"
        "email-validator"
        
        # Testing
        "pytest"
        "pytest-asyncio"
        
        # OpenVAS
        "gvm-tools"
        
        # OWASP ZAP
        "python-owasp-zap-v2.4"
    )
    
    for pkg in "${PYTHON_PACKAGES[@]}"; do
        log_info "Installing $pkg..."
        pip3 install "$pkg" --quiet 2>/dev/null && log_success "$pkg" || log_warn "$pkg failed"
    done
    
    # Install Playwright browsers
    log_info "Installing Playwright browsers..."
    playwright install chromium firefox 2>/dev/null || true
    playwright install-deps 2>/dev/null || true
    
    log_success "Python packages installed"
}

# ============================================================================
# MITMPROXY
# ============================================================================

install_mitmproxy() {
    log_section "Installing mitmproxy"
    
    pip3 install mitmproxy
    
    # Verify installation
    if command -v mitmproxy &> /dev/null; then
        log_success "mitmproxy installed: $(mitmproxy --version | head -1)"
    else
        log_warn "mitmproxy may need manual configuration"
    fi
}

# ============================================================================
# CHROMIUM & BROWSER DEPENDENCIES
# ============================================================================

install_browsers() {
    log_section "Installing Chromium & Browser Dependencies"
    
    apt install -y \
        chromium-browser \
        chromium-chromedriver \
        firefox \
        xvfb \
        libgbm1 \
        libnss3 \
        libatk1.0-0 \
        libatk-bridge2.0-0 \
        libcups2 \
        libdrm2 \
        libxkbcommon0 \
        libxcomposite1 \
        libxdamage1 \
        libxfixes3 \
        libxrandr2 \
        libpango-1.0-0 \
        libcairo2 \
        libasound2 \
        libatspi2.0-0 || log_warn "Some browser deps failed"
    
    # Install geckodriver for Firefox
    GECKO_VERSION="0.34.0"
    if ! command -v geckodriver &> /dev/null; then
        wget -q "https://github.com/mozilla/geckodriver/releases/download/v${GECKO_VERSION}/geckodriver-v${GECKO_VERSION}-linux64.tar.gz" -O /tmp/geckodriver.tar.gz
        tar -xzf /tmp/geckodriver.tar.gz -C /usr/local/bin/
        chmod +x /usr/local/bin/geckodriver
        rm /tmp/geckodriver.tar.gz
    fi
    
    log_success "Browsers and dependencies installed"
}

# ============================================================================
# ANDROID SDK & EMULATOR
# ============================================================================

install_android_sdk() {
    log_section "Installing Android SDK & Emulator"
    
    ANDROID_HOME="/opt/android-sdk"
    CMDLINE_TOOLS_VERSION="11076708"
    
    # Install Java (required for Android SDK)
    apt install -y openjdk-17-jdk
    
    # Create Android SDK directory
    mkdir -p $ANDROID_HOME/cmdline-tools
    
    # Download command-line tools
    if [ ! -d "$ANDROID_HOME/cmdline-tools/latest" ]; then
        log_info "Downloading Android command-line tools..."
        wget -q "https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_TOOLS_VERSION}_latest.zip" -O /tmp/cmdline-tools.zip
        unzip -q /tmp/cmdline-tools.zip -d /tmp/
        mv /tmp/cmdline-tools $ANDROID_HOME/cmdline-tools/latest
        rm /tmp/cmdline-tools.zip
    fi
    
    # Set environment variables
    cat > /etc/profile.d/android.sh << EOF
export ANDROID_HOME=$ANDROID_HOME
export ANDROID_SDK_ROOT=$ANDROID_HOME
export PATH=\$PATH:\$ANDROID_HOME/cmdline-tools/latest/bin
export PATH=\$PATH:\$ANDROID_HOME/platform-tools
export PATH=\$PATH:\$ANDROID_HOME/emulator
export PATH=\$PATH:\$ANDROID_HOME/build-tools/34.0.0
EOF
    
    source /etc/profile.d/android.sh
    
    # Accept licenses
    yes | $ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager --licenses 2>/dev/null || true
    
    # Install SDK components
    log_info "Installing Android SDK components (this may take a while)..."
    $ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager --install \
        "platform-tools" \
        "platforms;android-34" \
        "build-tools;34.0.0" \
        "emulator" \
        "system-images;android-34;google_apis;x86_64" \
        2>/dev/null || log_warn "Some SDK components may have failed"
    
    # Create AVD (Android Virtual Device)
    log_info "Creating Android Virtual Device..."
    echo "no" | $ANDROID_HOME/cmdline-tools/latest/bin/avdmanager create avd -n jarwis_emulator -k "system-images;android-34;google_apis;x86_64" --force 2>/dev/null || true
    
    # Install KVM for hardware acceleration
    apt install -y qemu-kvm libvirt-daemon-system 2>/dev/null || true
    adduser $SUDO_USER kvm 2>/dev/null || true
    
    log_success "Android SDK installed at $ANDROID_HOME"
}

# ============================================================================
# FRIDA SERVER & TOOLS
# ============================================================================

install_frida() {
    log_section "Installing Frida"
    
    # Install Frida tools via pip
    pip3 install frida-tools frida objection
    
    # Get Frida version
    FRIDA_VERSION=$(python3 -c "import frida; print(frida.__version__)" 2>/dev/null || echo "16.1.4")
    FRIDA_SERVER_DIR="/opt/frida"
    mkdir -p $FRIDA_SERVER_DIR
    
    log_info "Downloading Frida server v${FRIDA_VERSION} for Android..."
    
    # x86_64 (for emulator)
    wget -q "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-x86_64.xz" \
        -O /tmp/frida-server-x86_64.xz 2>/dev/null || log_warn "Frida x86_64 download failed"
    
    if [ -f /tmp/frida-server-x86_64.xz ]; then
        xz -d /tmp/frida-server-x86_64.xz
        mv /tmp/frida-server-x86_64 $FRIDA_SERVER_DIR/frida-server-x86_64
        chmod +x $FRIDA_SERVER_DIR/frida-server-x86_64
        log_success "Frida server x86_64 downloaded"
    fi
    
    # ARM64 (for physical devices)
    wget -q "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-arm64.xz" \
        -O /tmp/frida-server-arm64.xz 2>/dev/null || log_warn "Frida arm64 download failed"
    
    if [ -f /tmp/frida-server-arm64.xz ]; then
        xz -d /tmp/frida-server-arm64.xz
        mv /tmp/frida-server-arm64 $FRIDA_SERVER_DIR/frida-server-arm64
        chmod +x $FRIDA_SERVER_DIR/frida-server-arm64
        log_success "Frida server arm64 downloaded"
    fi
    
    # ARM (for older devices)
    wget -q "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-arm.xz" \
        -O /tmp/frida-server-arm.xz 2>/dev/null || log_warn "Frida arm download failed"
    
    if [ -f /tmp/frida-server-arm.xz ]; then
        xz -d /tmp/frida-server-arm.xz
        mv /tmp/frida-server-arm $FRIDA_SERVER_DIR/frida-server-arm
        chmod +x $FRIDA_SERVER_DIR/frida-server-arm
        log_success "Frida server arm downloaded"
    fi
    
    log_success "Frida installed"
    log_info "Frida servers saved to $FRIDA_SERVER_DIR"
}

# ============================================================================
# MOBILE SECURITY TOOLS
# ============================================================================

install_mobile_tools() {
    log_section "Installing Mobile Security Tools"
    
    # APK tools
    apt install -y \
        apktool \
        zipalign \
        aapt \
        smali 2>/dev/null || log_warn "Some APK tools failed"
    
    # Install dex2jar
    if [ ! -d "/opt/dex2jar" ]; then
        log_info "Installing dex2jar..."
        wget -q "https://github.com/pxb1988/dex2jar/releases/download/v2.4/dex-tools-v2.4.zip" -O /tmp/dex2jar.zip
        unzip -q /tmp/dex2jar.zip -d /opt/
        mv /opt/dex-tools-* /opt/dex2jar
        chmod +x /opt/dex2jar/*.sh
        ln -sf /opt/dex2jar/d2j-dex2jar.sh /usr/local/bin/dex2jar
        rm /tmp/dex2jar.zip
    fi
    
    # Install JADX (Java Decompiler)
    if [ ! -d "/opt/jadx" ]; then
        log_info "Installing JADX..."
        JADX_VERSION="1.4.7"
        wget -q "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" -O /tmp/jadx.zip
        unzip -q /tmp/jadx.zip -d /opt/jadx
        chmod +x /opt/jadx/bin/*
        ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx
        ln -sf /opt/jadx/bin/jadx-gui /usr/local/bin/jadx-gui
        rm /tmp/jadx.zip
    fi
    
    # Install Apktool latest
    if [ ! -f "/usr/local/bin/apktool" ]; then
        log_info "Installing latest Apktool..."
        wget -q "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool" -O /usr/local/bin/apktool
        wget -q "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar" -O /usr/local/bin/apktool.jar
        chmod +x /usr/local/bin/apktool
    fi
    
    # MobSF dependencies
    pip3 install mobsf 2>/dev/null || log_warn "MobSF install may need manual setup"
    
    log_success "Mobile security tools installed"
}

# ============================================================================
# WEB SECURITY TOOLS
# ============================================================================

install_web_tools() {
    log_section "Installing Web Security Tools"
    
    # Install Nikto
    apt install -y nikto
    
    # Install SQLMap
    apt install -y sqlmap
    
    # Install dirb/dirbuster alternatives
    apt install -y dirb gobuster
    
    # Install wfuzz
    pip3 install wfuzz
    
    # Install WPScan
    apt install -y ruby-full
    gem install wpscan 2>/dev/null || log_warn "WPScan install failed"
    
    # Install OWASP ZAP
    log_info "Installing OWASP ZAP..."
    if [ ! -d "/opt/zaproxy" ]; then
        ZAP_VERSION="2.14.0"
        wget -q "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" -O /tmp/zap.tar.gz
        tar -xzf /tmp/zap.tar.gz -C /opt/
        mv /opt/ZAP_${ZAP_VERSION} /opt/zaproxy
        ln -sf /opt/zaproxy/zap.sh /usr/local/bin/zap
        rm /tmp/zap.tar.gz
        log_success "OWASP ZAP installed"
    fi
    
    log_success "Web security tools installed"
}

# ============================================================================
# METASPLOIT FRAMEWORK
# ============================================================================

install_metasploit() {
    log_section "Installing Metasploit Framework"
    
    if ! command -v msfconsole &> /dev/null; then
        log_info "Downloading Metasploit installer..."
        curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall
        chmod 755 /tmp/msfinstall
        /tmp/msfinstall
        rm /tmp/msfinstall
        log_success "Metasploit installed"
    else
        log_success "Metasploit already installed"
    fi
}

# ============================================================================
# VERIFICATION
# ============================================================================

verify_installation() {
    log_section "Verifying Installation"
    
    echo ""
    echo "System Tools:"
    echo "============="
    
    TOOLS=(
        "python3:Python"
        "node:Node.js"
        "go:Go"
        "cargo:Rust"
        "psql:PostgreSQL"
        "nmap:Nmap"
        "masscan:Masscan"
        "rustscan:RustScan"
        "nuclei:Nuclei"
        "httpx:httpx"
        "ffuf:ffuf"
        "subfinder:Subfinder"
        "sslscan:SSLScan"
        "testssl.sh:testssl.sh"
        "tshark:tshark"
        "tcpdump:tcpdump"
        "suricata:Suricata"
        "mitmproxy:mitmproxy"
        "frida:Frida"
        "objection:Objection"
        "adb:Android ADB"
        "emulator:Android Emulator"
        "chromium-browser:Chromium"
        "firefox:Firefox"
        "nikto:Nikto"
        "sqlmap:SQLMap"
        "gobuster:Gobuster"
        "hydra:Hydra"
        "jadx:JADX"
        "apktool:Apktool"
        "zap:OWASP ZAP"
    )
    
    installed=0
    total=${#TOOLS[@]}
    
    for item in "${TOOLS[@]}"; do
        cmd=$(echo $item | cut -d: -f1)
        name=$(echo $item | cut -d: -f2)
        if command -v $cmd &> /dev/null; then
            echo -e "  ${GREEN}[OK]${NC} $name"
            ((installed++))
        else
            echo -e "  ${RED}[X]${NC} $name"
        fi
    done
    
    echo ""
    echo "Python Packages:"
    echo "================"
    
    PYTHON_PKGS=(
        "nmap:python-nmap"
        "sslyze:sslyze"
        "impacket:impacket"
        "frida:frida"
        "mitmproxy:mitmproxy"
        "playwright:playwright"
        "fastapi:fastapi"
        "boto3:boto3"
        "androguard:androguard"
        "scapy:scapy"
    )
    
    for item in "${PYTHON_PKGS[@]}"; do
        pkg=$(echo $item | cut -d: -f1)
        name=$(echo $item | cut -d: -f2)
        if python3 -c "import $pkg" 2>/dev/null; then
            echo -e "  ${GREEN}[OK]${NC} $name"
        else
            echo -e "  ${RED}[X]${NC} $name"
        fi
    done
    
    echo ""
    echo "========================================"
    echo "Installation complete: $installed/$total core tools verified"
    echo "========================================"
}

# ============================================================================
# CLEANUP
# ============================================================================

cleanup() {
    log_section "Cleaning Up"
    
    apt autoremove -y
    apt clean
    rm -rf /tmp/*.deb /tmp/*.tar.gz /tmp/*.zip /tmp/*.xz
    
    log_success "Cleanup complete"
}

# ============================================================================
# CREATE HELPER SCRIPTS
# ============================================================================

create_helper_scripts() {
    log_section "Creating Helper Scripts"
    
    # Script to start Android emulator
    cat > /usr/local/bin/jarwis-start-emulator << 'EOF'
#!/bin/bash
source /etc/profile.d/android.sh
emulator -avd jarwis_emulator -no-audio -no-window &
echo "Waiting for emulator to boot..."
adb wait-for-device
sleep 30
echo "Emulator ready!"
EOF
    chmod +x /usr/local/bin/jarwis-start-emulator
    
    # Script to push Frida server to device
    cat > /usr/local/bin/jarwis-push-frida << 'EOF'
#!/bin/bash
ARCH=${1:-x86_64}
FRIDA_SERVER="/opt/frida/frida-server-$ARCH"

if [ ! -f "$FRIDA_SERVER" ]; then
    echo "Frida server for $ARCH not found at $FRIDA_SERVER"
    exit 1
fi

adb root
adb push $FRIDA_SERVER /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
echo "Frida server pushed. Start with: adb shell /data/local/tmp/frida-server &"
EOF
    chmod +x /usr/local/bin/jarwis-push-frida
    
    # Script to start Jarwis API
    cat > /usr/local/bin/jarwis-start << 'EOF'
#!/bin/bash
cd /opt/jarwis-ai-pentest 2>/dev/null || cd ~/jarwis-ai-pentest
source venv/bin/activate 2>/dev/null || true
python3 -m uvicorn api.app:app --host 0.0.0.0 --port 8000
EOF
    chmod +x /usr/local/bin/jarwis-start
    
    log_success "Helper scripts created"
    log_info "Available commands:"
    log_info "  jarwis-start-emulator  - Start Android emulator"
    log_info "  jarwis-push-frida      - Push Frida server to device"
    log_info "  jarwis-start           - Start Jarwis API server"
}

# ============================================================================
# MAIN
# ============================================================================

main() {
    echo ""
    echo "=============================================="
    echo "  JARWIS AGI PEN TEST - FULL INSTALLATION"
    echo "=============================================="
    echo "  Mode: $INSTALL_MODE"
    echo "  Skip Mobile: $SKIP_MOBILE"
    echo "=============================================="
    echo ""
    
    check_root
    
    case $INSTALL_MODE in
        "minimal")
            install_prerequisites
            install_python
            install_python_packages
            ;;
        "network")
            install_prerequisites
            install_python
            install_golang
            install_network_tools
            install_go_tools
            install_python_packages
            ;;
        "mobile")
            install_prerequisites
            install_python
            install_android_sdk
            install_frida
            install_mobile_tools
            ;;
        "web")
            install_prerequisites
            install_python
            install_nodejs
            install_browsers
            install_mitmproxy
            install_web_tools
            install_python_packages
            ;;
        "all"|*)
            install_prerequisites
            install_python
            install_nodejs
            install_golang
            install_rust
            install_postgresql
            install_network_tools
            install_go_tools
            install_browsers
            install_mitmproxy
            install_web_tools
            
            if [ "$SKIP_MOBILE" = false ]; then
                install_android_sdk
                install_frida
                install_mobile_tools
            fi
            
            install_python_packages
            create_helper_scripts
            ;;
    esac
    
    cleanup
    verify_installation
    
    echo ""
    log_success "Installation complete!"
    echo ""
    echo "Next steps:"
    echo "  1. Source the environment: source /etc/profile.d/*.sh"
    echo "  2. Restart your shell or log out/in"
    echo "  3. Run 'python3 requiredtools.py --check' to verify"
    echo ""
    echo "For mobile testing:"
    echo "  - Start emulator: jarwis-start-emulator"
    echo "  - Push Frida: jarwis-push-frida x86_64"
    echo ""
    echo "Frida servers location: /opt/frida/"
    echo "Android SDK location: /opt/android-sdk/"
    echo ""
}

# Run main
main "$@"
