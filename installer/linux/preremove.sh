#!/bin/bash
# ===========================================================================
# Jarwis Agent - Linux Pre-Remove Script
# ===========================================================================
#
# Runs before package removal.
# Stops the service gracefully.
#
# ===========================================================================

set -e

echo "Jarwis Agent: Stopping service..."

# Stop service
systemctl stop jarwis-agent.service 2>/dev/null || true
systemctl disable jarwis-agent.service 2>/dev/null || true

echo "Jarwis Agent: Service stopped"

exit 0
