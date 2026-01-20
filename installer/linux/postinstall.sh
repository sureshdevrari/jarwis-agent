#!/bin/bash
# ===========================================================================
# Jarwis Agent - Linux Post-Install Script
# ===========================================================================
#
# Runs after package installation.
# Creates directories and enables the service.
#
# ===========================================================================

set -e

echo "Jarwis Agent: Running post-install..."

# Create directories
mkdir -p /var/lib/jarwis
mkdir -p /var/log/jarwis
mkdir -p /etc/jarwis

# Set permissions
chmod 755 /usr/bin/jarwis-agent
chmod 755 /var/lib/jarwis
chmod 755 /var/log/jarwis
chmod 644 /etc/jarwis/config.yaml

# Reload systemd
systemctl daemon-reload

# Enable service (but don't start - need activation)
systemctl enable jarwis-agent.service || true

echo ""
echo "============================================================"
echo "  Jarwis Agent installed successfully!"
echo "============================================================"
echo ""
echo "To activate the agent, run:"
echo "  sudo jarwis-agent --activate YOUR_ACTIVATION_KEY"
echo ""
echo "Or configure manually:"
echo "  sudo nano /etc/jarwis/config.yaml"
echo "  sudo systemctl start jarwis-agent"
echo ""
echo "Check status:"
echo "  sudo systemctl status jarwis-agent"
echo "  sudo journalctl -u jarwis-agent -f"
echo ""

exit 0
