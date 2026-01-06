#!/usr/bin/env python3
"""
JARWIS AGI PEN TEST - Main Entry Point
OWASP Top 10 AI-Powered Penetration Testing Tool

Interactive CLI that prompts user for target website and credentials.
"""

import sys
import asyncio
import os
from datetime import datetime
from getpass import getpass

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_banner():
    """Display the Jarwis banner"""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
     â-ˆâ-ˆâ*-- â-ˆâ-ˆâ-ˆâ-ˆâ-ˆâ*-- â-ˆâ-ˆâ-ˆâ-ˆâ-ˆâ-ˆâ*-- â-ˆâ-ˆâ*--    â-ˆâ-ˆâ*--â-ˆâ-ˆâ*--â-ˆâ-ˆâ-ˆâ-ˆâ-ˆâ-ˆâ-ˆâ*--
     â-ˆâ-ˆâ*'â-ˆâ-ˆâ*"â*â*â-ˆâ-ˆâ*--â-ˆâ-ˆâ*"â*â*â-ˆâ-ˆâ*--â-ˆâ-ˆâ*'    â-ˆâ-ˆâ*'â-ˆâ-ˆâ*'â-ˆâ-ˆâ*"â*â*â*â*â*
     â-ˆâ-ˆâ*'â-ˆâ-ˆâ-ˆâ-ˆâ-ˆâ-ˆâ-ˆâ*'â-ˆâ-ˆâ-ˆâ-ˆâ-ˆâ-ˆâ*"â*â-ˆâ-ˆâ*' â-ˆâ*-- â-ˆâ-ˆâ*'â-ˆâ-ˆâ*'â-ˆâ-ˆâ-ˆâ-ˆâ-ˆâ-ˆâ-ˆâ*--
â-ˆâ-ˆ   â-ˆâ-ˆâ*'â-ˆâ-ˆâ*"â*â*â-ˆâ-ˆâ*'â-ˆâ-ˆâ*"â*â*â-ˆâ-ˆâ*--â-ˆâ-ˆâ*'â-ˆâ-ˆâ-ˆâ*--â-ˆâ-ˆâ*'â-ˆâ-ˆâ*'â*šâ*â*â*â*â-ˆâ-ˆâ*'
â*šâ-ˆâ-ˆâ-ˆâ-ˆâ-ˆâ*"â*â-ˆâ-ˆâ*'  â-ˆâ-ˆâ*'â-ˆâ-ˆâ*'  â-ˆâ-ˆâ*'â*šâ-ˆâ-ˆâ-ˆâ*"â-ˆâ-ˆâ-ˆâ*"â*â-ˆâ-ˆâ*'â-ˆâ-ˆâ-ˆâ-ˆâ-ˆâ-ˆâ-ˆâ*'
 â*šâ*â*â*â*â* â*šâ*â*  â*šâ*â*â*šâ*â*  â*šâ*â* â*šâ*â*â*â*šâ*â*â* â*šâ*â*â*šâ*â*â*â*â*â*â*
{Colors.ENDC}
{Colors.GREEN}    AI-Powered OWASP Top 10 Penetration Testing{Colors.ENDC}
{Colors.WARNING}    âš ï¸  Use only on authorized targets!{Colors.ENDC}
    """
    print(banner)

def print_section(title):
    """Print a section header"""
    print(f"\n{Colors.BLUE}{Colors.BOLD}{'='*50}")
    print(f"  {title}")
    print(f"{'='*50}{Colors.ENDC}\n")

def get_input(prompt, default=None, required=True):
    """Get user input with optional default value"""
    if default:
        user_input = input(f"{Colors.CYAN}{prompt} [{default}]: {Colors.ENDC}").strip()
        return user_input if user_input else default
    else:
        while True:
            user_input = input(f"{Colors.CYAN}{prompt}: {Colors.ENDC}").strip()
            if user_input or not required:
                return user_input
            print(f"{Colors.FAIL}This field is required!{Colors.ENDC}")

def get_yes_no(prompt, default="y"):
    """Get yes/no input from user"""
    default_str = "Y/n" if default.lower() == "y" else "y/N"
    while True:
        response = input(f"{Colors.CYAN}{prompt} [{default_str}]: {Colors.ENDC}").strip().lower()
        if not response:
            return default.lower() == "y"
        if response in ["y", "yes"]:
            return True
        if response in ["n", "no"]:
            return False
        print(f"{Colors.FAIL}Please enter 'y' or 'n'{Colors.ENDC}")

def get_password(prompt):
    """Get password input (hidden)"""
    return getpass(f"{Colors.CYAN}{prompt}: {Colors.ENDC}")

def select_option(prompt, options):
    """Display numbered options and get user selection"""
    print(f"{Colors.CYAN}{prompt}{Colors.ENDC}")
    for i, option in enumerate(options, 1):
        print(f"  {Colors.GREEN}{i}.{Colors.ENDC} {option}")
    
    while True:
        try:
            choice = input(f"{Colors.CYAN}Enter choice [1-{len(options)}]: {Colors.ENDC}").strip()
            choice_num = int(choice)
            if 1 <= choice_num <= len(options):
                return choice_num - 1
            print(f"{Colors.FAIL}Please enter a number between 1 and {len(options)}{Colors.ENDC}")
        except ValueError:
            print(f"{Colors.FAIL}Please enter a valid number{Colors.ENDC}")

def get_network_scan_configuration():
    """Interactive prompts for network security scan configuration"""
    config = {
        "scan_type": "network",
        "network": {},
        "credentials": {},
        "ai": {},
        "output": {}
    }
    
    # Section 1: Target Configuration
    print_section("NETWORK TARGET CONFIGURATION")
    
    print(f"{Colors.CYAN}Specify IP addresses, subnets, or ranges to scan:{Colors.ENDC}")
    print(f"  Examples: 192.168.1.1, 10.0.0.0/24, 172.16.0.1-50")
    
    config["network"]["targets"] = get_input("Enter IP/Subnet to scan")
    config["network"]["exclude_targets"] = get_input("Exclude IPs (optional)", default="", required=False)
    
    # Check for private IPs
    import ipaddress
    has_private = False
    for target in config["network"]["targets"].split(','):
        target = target.strip()
        try:
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                if network.is_private:
                    has_private = True
            else:
                ip = ipaddress.ip_address(target.split('-')[0])
                if ip.is_private:
                    has_private = True
        except:
            pass
    
    if has_private:
        print(f"\n{Colors.WARNING}âš ï¸  Private IP detected! To scan private networks:{Colors.ENDC}")
        print(f"   1. Register a Jarwis Agent from the dashboard")
        print(f"   2. Deploy the agent inside your network")
        print(f"   3. Use the agent_id for scanning")
        
        config["network"]["use_agent"] = get_yes_no("Use Jarwis Agent for this scan?", default="y")
        if config["network"]["use_agent"]:
            config["network"]["agent_id"] = get_input("Enter Agent ID")
    else:
        config["network"]["use_agent"] = False
    
    # Section 2: Scan Settings
    print_section("SCAN SETTINGS")
    
    config["network"]["host_discovery"] = get_yes_no("Enable host discovery (ping)?", default="y")
    config["network"]["port_scan_enabled"] = get_yes_no("Enable port scanning?", default="y")
    
    if config["network"]["port_scan_enabled"]:
        port_options = [
            "Common ports (top 25)",
            "Well-known ports (1-1024)",
            "Extended range (1-10000)",
            "All ports (1-65535)",
            "Custom range"
        ]
        port_choice = select_option("Port range to scan:", port_options)
        
        if port_choice == 0:
            config["network"]["port_range"] = "common"
        elif port_choice == 1:
            config["network"]["port_range"] = "1-1024"
        elif port_choice == 2:
            config["network"]["port_range"] = "1-10000"
        elif port_choice == 3:
            config["network"]["port_range"] = "all"
        else:
            config["network"]["port_range"] = get_input("Enter port range (e.g., 22,80,443,8080 or 1-1000)")
    
    config["network"]["service_detection"] = get_yes_no("Enable service/version detection?", default="y")
    config["network"]["vuln_scan_enabled"] = get_yes_no("Enable vulnerability scanning?", default="y")
    
    # Section 3: Credential-based Scanning (Nessus-style)
    print_section("CREDENTIAL-BASED SCANNING")
    print(f"{Colors.CYAN}Credential scanning enables deeper security checks{Colors.ENDC}")
    
    config["credentials"]["enabled"] = get_yes_no("Enable credential-based scanning?", default="n")
    
    if config["credentials"]["enabled"]:
        cred_types = [
            "SSH (Linux/Unix)",
            "Windows (SMB/WMI)",
            "SNMP (Network devices)",
            "Database (MySQL, PostgreSQL, etc.)",
            "All of the above"
        ]
        
        selected_creds = []
        print(f"\n{Colors.GREEN}Select credential types to configure:{Colors.ENDC}")
        for i, cred_type in enumerate(cred_types[:-1]):
            if get_yes_no(f"  Configure {cred_type}?", default="n"):
                selected_creds.append(cred_types.index(cred_type))
        
        # SSH Credentials
        if 0 in selected_creds:
            print(f"\n{Colors.BLUE}SSH Credentials:{Colors.ENDC}")
            config["credentials"]["ssh"] = {
                "username": get_input("  SSH Username"),
                "auth_method": "password" if get_yes_no("  Use password auth (vs key)?", default="y") else "key",
                "port": int(get_input("  SSH Port", default="22")),
            }
            if config["credentials"]["ssh"]["auth_method"] == "password":
                config["credentials"]["ssh"]["password"] = get_password("  SSH Password")
            else:
                config["credentials"]["ssh"]["private_key"] = get_input("  Path to private key file")
            
            if get_yes_no("  Enable privilege escalation (sudo)?", default="n"):
                config["credentials"]["ssh"]["privilege_escalation"] = "sudo"
                config["credentials"]["ssh"]["escalation_password"] = get_password("  Sudo password")
        
        # Windows Credentials
        if 1 in selected_creds:
            print(f"\n{Colors.BLUE}Windows Credentials:{Colors.ENDC}")
            config["credentials"]["windows"] = {
                "username": get_input("  Windows Username"),
                "password": get_password("  Windows Password"),
                "domain": get_input("  Domain (optional)", default="", required=False),
                "auth_method": "password"
            }
        
        # SNMP Credentials
        if 2 in selected_creds:
            print(f"\n{Colors.BLUE}SNMP Credentials:{Colors.ENDC}")
            snmp_version = select_option("  SNMP Version:", ["v1", "v2c", "v3"])
            config["credentials"]["snmp"] = {
                "version": ["v1", "v2c", "v3"][snmp_version]
            }
            if snmp_version < 2:
                config["credentials"]["snmp"]["community_string"] = get_input("  Community String", default="public")
            else:
                config["credentials"]["snmp"]["username"] = get_input("  SNMPv3 Username")
                config["credentials"]["snmp"]["auth_protocol"] = "SHA"
                config["credentials"]["snmp"]["auth_password"] = get_password("  Auth Password")
        
        # Database Credentials
        if 3 in selected_creds:
            print(f"\n{Colors.BLUE}Database Credentials:{Colors.ENDC}")
            db_types = ["mysql", "postgresql", "mssql", "oracle", "mongodb"]
            db_choice = select_option("  Database Type:", db_types)
            config["credentials"]["database"] = {
                "db_type": db_types[db_choice],
                "username": get_input("  DB Username"),
                "password": get_password("  DB Password"),
                "port": int(get_input("  DB Port (0 for default)", default="0")),
            }
    
    # Section 4: Performance
    print_section("PERFORMANCE SETTINGS")
    config["network"]["max_concurrent_hosts"] = int(get_input("Max concurrent hosts", default="10"))
    config["network"]["rate_limit"] = int(get_input("Packets per second", default="100"))
    config["network"]["timeout_per_host"] = int(get_input("Timeout per host (seconds)", default="300"))
    config["network"]["safe_checks"] = get_yes_no("Safe mode (less aggressive)?", default="y")
    
    # Section 5: Output
    print_section("OUTPUT CONFIGURATION")
    config["output"]["directory"] = get_input("Output directory", default="./reports")
    
    return config


def get_scan_configuration():
    """Interactive prompts to get scan configuration from user"""
    
    # First ask what type of scan
    print_section("SCAN TYPE SELECTION")
    scan_types = [
        "Web Application Scan",
        "Network Security Scan",
        "Mobile App Backend Scan",
        "Cloud Infrastructure Scan (Coming Soon)"
    ]
    scan_type_choice = select_option("What would you like to scan?", scan_types)
    
    if scan_type_choice == 1:
        return get_network_scan_configuration()
    elif scan_type_choice == 2:
        print(f"{Colors.WARNING}Mobile scanning - will scan backend APIs{Colors.ENDC}")
    elif scan_type_choice == 3:
        print(f"{Colors.FAIL}Cloud scanning coming soon!{Colors.ENDC}")
        sys.exit(0)
    
    config = {
        "target": {},
        "auth": {},
        "scan": {},
        "ai": {},
        "output": {}
    }
    
    config["scan_type"] = ["web", "network", "mobile", "cloud"][scan_type_choice]
    
    # Section 1: Target Configuration
    print_section("TARGET CONFIGURATION")
    
    config["target"]["url"] = get_input("Enter target website URL (e.g., https://example.com)")
    
    # Validate URL format
    if not config["target"]["url"].startswith(("http://", "https://")):
        config["target"]["url"] = "https://" + config["target"]["url"]
        print(f"{Colors.WARNING}Added https:// prefix: {config['target']['url']}{Colors.ENDC}")
    
    config["target"]["scope"] = get_input("Scope regex (leave empty for same domain)", default="", required=False)
    
    # Section 2: Authentication
    print_section("AUTHENTICATION SETTINGS")
    
    config["auth"]["enabled"] = get_yes_no("Does the target require login?")
    
    if config["auth"]["enabled"]:
        print(f"\n{Colors.GREEN}Enter login credentials:{Colors.ENDC}")
        config["auth"]["username"] = get_input("Username/Email")
        config["auth"]["password"] = get_password("Password")
        
        print(f"\n{Colors.GREEN}Login form selectors (press Enter for defaults):{Colors.ENDC}")
        config["auth"]["login_url"] = get_input("Login page URL path", default="/login")
        config["auth"]["username_selector"] = get_input("Username field selector", default="input[name='username'], input[name='email'], #username, #email")
        config["auth"]["password_selector"] = get_input("Password field selector", default="input[name='password'], input[type='password'], #password")
        config["auth"]["submit_selector"] = get_input("Submit button selector", default="button[type='submit'], input[type='submit'], #login-btn")
        config["auth"]["success_indicator"] = get_input("Success indicator (URL/text after login)", default="/dashboard")
    
    # Section 3: Scan Options
    print_section("SCAN OPTIONS")
    
    scan_types = [
        "Full OWASP Top 10 Scan (Recommended)",
        "Quick Scan (Injection + XSS only)",
        "API Security Scan",
        "Custom Selection"
    ]
    scan_choice = select_option("Select scan type:", scan_types)
    
    if scan_choice == 0:  # Full scan
        config["scan"]["modules"] = ["injection", "xss", "sensitive_data", "misconfig", "upload", "api", "idor", "csrf", "privesc"]
    elif scan_choice == 1:  # Quick scan
        config["scan"]["modules"] = ["injection", "xss"]
    elif scan_choice == 2:  # API scan
        config["scan"]["modules"] = ["api", "injection"]
    else:  # Custom
        print(f"\n{Colors.GREEN}Select modules to enable:{Colors.ENDC}")
        available_modules = [
            ("injection", "SQL/Command/NoSQL Injection (A03)"),
            ("xss", "Cross-Site Scripting (A03)"),
            ("sensitive_data", "Sensitive Data Exposure (A02)"),
            ("misconfig", "Security Misconfiguration (A05)"),
            ("upload", "File Upload Vulnerabilities (A04)"),
            ("api", "API Security Testing (A01)"),
            ("idor", "IDOR Testing (A01) - Requires Auth"),
            ("csrf", "CSRF Testing (A01) - Requires Auth"),
            ("privesc", "Privilege Escalation (A01) - Requires Auth")
        ]
        config["scan"]["modules"] = []
        for module_id, module_desc in available_modules:
            if get_yes_no(f"  Enable {module_desc}?"):
                config["scan"]["modules"].append(module_id)
    
    config["scan"]["rate_limit"] = int(get_input("Requests per second", default="10"))
    config["scan"]["timeout"] = int(get_input("Request timeout (seconds)", default="30"))
    
    # Section 4: AI Configuration
    print_section("AI CONFIGURATION")
    
    config["ai"]["enabled"] = get_yes_no("Enable AI-powered test planning?", default="y")
    
    if config["ai"]["enabled"]:
        ai_providers = ["Ollama (Local/Free)", "OpenAI (Cloud/Paid)"]
        ai_choice = select_option("Select AI provider:", ai_providers)
        
        if ai_choice == 0:
            config["ai"]["provider"] = "ollama"
            config["ai"]["model"] = get_input("Ollama model name", default="llama3")
            config["ai"]["base_url"] = get_input("Ollama URL", default="http://localhost:11434")
        else:
            config["ai"]["provider"] = "openai"
            config["ai"]["api_key"] = get_password("OpenAI API Key")
            config["ai"]["model"] = get_input("OpenAI model", default="gpt-4")
    
    # Section 5: Output Configuration
    print_section("OUTPUT CONFIGURATION")
    
    config["output"]["directory"] = get_input("Output directory", default="./reports")
    
    print(f"{Colors.GREEN}Select report formats:{Colors.ENDC}")
    config["output"]["formats"] = []
    if get_yes_no("  Generate HTML report?", default="y"):
        config["output"]["formats"].append("html")
    if get_yes_no("  Generate JSON report?", default="y"):
        config["output"]["formats"].append("json")
    if get_yes_no("  Generate SARIF report (for CI/CD)?", default="n"):
        config["output"]["formats"].append("sarif")
    
    return config

def display_config_summary(config):
    """Display a summary of the configuration before starting"""
    print_section("CONFIGURATION SUMMARY")
    
    print(f"{Colors.GREEN}Target:{Colors.ENDC} {config['target']['url']}")
    print(f"{Colors.GREEN}Authentication:{Colors.ENDC} {'Enabled' if config['auth'].get('enabled') else 'Disabled'}")
    if config['auth'].get('enabled'):
        print(f"  - Username: {config['auth']['username']}")
        print(f"  - Login URL: {config['auth']['login_url']}")
    print(f"{Colors.GREEN}Scan Modules:{Colors.ENDC} {', '.join(config['scan']['modules'])}")
    print(f"{Colors.GREEN}Rate Limit:{Colors.ENDC} {config['scan']['rate_limit']} req/s")
    print(f"{Colors.GREEN}AI Planning:{Colors.ENDC} {'Enabled (' + config['ai'].get('provider', 'N/A') + ')' if config['ai'].get('enabled') else 'Disabled'}")
    print(f"{Colors.GREEN}Output:{Colors.ENDC} {config['output']['directory']} ({', '.join(config['output']['formats'])})")

def save_config_to_yaml(config, filepath):
    """Save configuration to YAML file"""
    import yaml
    
    yaml_config = {
        "target": {
            "url": config["target"]["url"],
            "scope": config["target"].get("scope", "")
        },
        "auth": {
            "enabled": config["auth"].get("enabled", False),
            "type": "form",
            "credentials": {
                "username": config["auth"].get("username", ""),
                "password": config["auth"].get("password", "")
            },
            "selectors": {
                "login_url": config["auth"].get("login_url", "/login"),
                "username_field": config["auth"].get("username_selector", ""),
                "password_field": config["auth"].get("password_selector", ""),
                "submit_button": config["auth"].get("submit_selector", ""),
                "success_indicator": config["auth"].get("success_indicator", "")
            }
        },
        "scan": {
            "rate_limit": config["scan"].get("rate_limit", 10),
            "timeout": config["scan"].get("timeout", 30),
            "modules": config["scan"].get("modules", [])
        },
        "ai": {
            "enabled": config["ai"].get("enabled", False),
            "provider": config["ai"].get("provider", "ollama"),
            "model": config["ai"].get("model", "llama3"),
            "base_url": config["ai"].get("base_url", "http://localhost:11434"),
            "api_key": config["ai"].get("api_key", "")
        },
        "output": {
            "directory": config["output"].get("directory", "./reports"),
            "formats": config["output"].get("formats", ["html", "json"])
        }
    }
    
    os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else ".", exist_ok=True)
    with open(filepath, "w") as f:
        yaml.dump(yaml_config, f, default_flow_style=False)
    
    return filepath

async def run_scan(config):
    """Execute the penetration test scan"""
    
    scan_type = config.get("scan_type", "web")
    
    if scan_type == "network":
        await run_network_scan(config)
    else:
        await run_web_scan(config)


async def run_network_scan(config):
    """Execute network security scan"""
    from attacks.network import NetworkSecurityScanner
    from attacks.network.network_scanner import NetworkScanContext
    
    print_section("STARTING NETWORK SCAN")
    print(f"{Colors.WARNING}âš ï¸  Scanning targets: {config['network']['targets']}{Colors.ENDC}")
    print(f"{Colors.CYAN}Press Ctrl+C to stop at any time{Colors.ENDC}\n")
    
    # Create context
    context = NetworkScanContext(
        targets=config['network']['targets'].split(','),
        use_agent=config['network'].get('use_agent', False),
        agent_id=config['network'].get('agent_id'),
        credentials=config.get('credentials') if config.get('credentials', {}).get('enabled') else None
    )
    
    # Create scanner
    scanner = NetworkSecurityScanner(
        config={'network_config': config['network']},
        context=context
    )
    
    # Run scan
    findings = await scanner.scan()
    
    # Display results
    print_section("SCAN RESULTS")
    
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for finding in findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
    
    print(f"{Colors.GREEN}Total Findings: {len(findings)}{Colors.ENDC}")
    print(f"  {Colors.FAIL}Critical: {severity_counts['critical']}{Colors.ENDC}")
    print(f"  {Colors.WARNING}High: {severity_counts['high']}{Colors.ENDC}")
    print(f"  {Colors.CYAN}Medium: {severity_counts['medium']}{Colors.ENDC}")
    print(f"  {Colors.GREEN}Low: {severity_counts['low']}{Colors.ENDC}")
    print(f"  Info: {severity_counts['info']}")
    
    # Display top findings
    critical_high = [f for f in findings if f.severity in ['critical', 'high']]
    if critical_high:
        print(f"\n{Colors.FAIL}Critical/High Findings:{Colors.ENDC}")
        for finding in critical_high[:10]:
            print(f"  [{finding.severity.upper()}] {finding.title}")
            print(f"    IP: {finding.ip_address}:{finding.port or 'N/A'}")
            if finding.cve_id:
                print(f"    CVE: {finding.cve_id}")
    
    # Save report
    output_dir = config['output'].get('directory', './reports')
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(output_dir, f"network_scan_{timestamp}.json")
    
    import json
    with open(report_path, 'w') as f:
        json.dump({
            'scan_type': 'network',
            'targets': config['network']['targets'],
            'timestamp': timestamp,
            'findings': [
                {
                    'id': f.id,
                    'category': f.category,
                    'severity': f.severity,
                    'title': f.title,
                    'description': f.description,
                    'ip_address': f.ip_address,
                    'port': f.port,
                    'service': f.service,
                    'cve_id': f.cve_id,
                    'remediation': f.remediation,
                }
                for f in findings
            ],
            'summary': severity_counts
        }, f, indent=2)
    
    print(f"\n{Colors.GREEN}Report saved to: {report_path}{Colors.ENDC}")


async def run_web_scan(config):
    """Execute the web application penetration test scan"""
    from core.runner import PenTestRunner
    
    print_section("STARTING SCAN")
    print(f"{Colors.WARNING}âš ï¸  Scanning {config['target']['url']}{Colors.ENDC}")
    print(f"{Colors.CYAN}Press Ctrl+C to stop at any time{Colors.ENDC}\n")
    
    # Create runner and execute
    runner = PenTestRunner(config)
    await runner.run()

def main():
    """Main entry point with interactive prompts"""
    print_banner()
    
    # Check for command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] in ["-h", "--help"]:
            print(f"""
{Colors.BOLD}Usage:{Colors.ENDC}
  python main.py              Interactive mode (prompts for input)
  python main.py --config FILE    Use existing config file
  python main.py --help           Show this help message

{Colors.BOLD}Examples:{Colors.ENDC}
  python main.py
  python main.py --config config/config.yaml
""")
            sys.exit(0)
        elif sys.argv[1] == "--config" and len(sys.argv) > 2:
            # Use existing config file
            config_file = sys.argv[2]
            print(f"{Colors.GREEN}Using config file: {config_file}{Colors.ENDC}")
            from core.runner import main as runner_main
            runner_main()
            return
    
    # Interactive mode
    try:
        # Get configuration from user
        config = get_scan_configuration()
        
        # Display summary
        display_config_summary(config)
        
        # Confirm before starting
        print()
        if not get_yes_no(f"{Colors.BOLD}Start scan with these settings?{Colors.ENDC}", default="y"):
            print(f"{Colors.WARNING}Scan cancelled.{Colors.ENDC}")
            sys.exit(0)
        
        # Save config for future use
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        config_path = f"config/scan_{timestamp}.yaml"
        save_config_to_yaml(config, config_path)
        print(f"\n{Colors.GREEN}Configuration saved to: {config_path}{Colors.ENDC}")
        
        # Create output directory
        os.makedirs(config["output"]["directory"], exist_ok=True)
        
        # Run the scan
        asyncio.run(run_scan(config))
        
    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}Scan interrupted by user{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.FAIL}Error: {e}{Colors.ENDC}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
