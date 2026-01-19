#!/bin/bash
# ===========================================================================
# Jarwis Agent - Linux Post-Remove Script
# ===========================================================================
#
# Runs after package removal.
# Cleans up runtime data (preserves config for reinstall).
#
# ===========================================================================

set -e

echo "Jarwis Agent: Cleaning up..."

# Remove runtime data
rm -rf /var/lib/jarwis
rm -rf /var/log/jarwis

# Reload systemd
systemctl daemon-reload

# Note: /etc/jarwis is preserved for reinstall
echo "Configuration preserved in /etc/jarwis"
echo "To fully remove: sudo rm -rf /etc/jarwis"

exit 0
