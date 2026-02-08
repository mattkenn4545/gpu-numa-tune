#!/bin/bash

# ==============================================================================
# GPU NUMA Optimizer - Installer/Updater
# ==============================================================================
# Purpose:
#   Automates the installation or update of the GPU NUMA Optimizer script
#   and its associated systemd service.
#
# Actions:
#   1. Copies the script to /usr/local/bin.
#   2. Installs the systemd service file to /etc/systemd/system.
#   3. Reloads systemd and enables/restarts the service.
#
# Usage:
#   sudo ./install.sh
# ==============================================================================

set -e

# Configuration
BIN_NAME="gpu_optimize.sh"
SERVICE_NAME="gpu-numa-optimizer.service"
CONFIG_NAME="gpu-numa-tune.conf"
INSTALL_BIN_PATH="/usr/local/bin/$BIN_NAME"
INSTALL_SERVICE_PATH="/etc/systemd/system/$SERVICE_NAME"
INSTALL_CONFIG_PATH="/etc/$CONFIG_NAME"

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

echo "--- GPU NUMA Tune Installer/Updater ---"

# 1. Install/Update the binary
echo "Installing/Updating $BIN_NAME to $INSTALL_BIN_PATH..."
cp "$BIN_NAME" "$INSTALL_BIN_PATH"
chmod +x "$INSTALL_BIN_PATH"

# 2. Install/Update the service file
echo "Installing/Updating $SERVICE_NAME to $INSTALL_SERVICE_PATH..."
cp "$SERVICE_NAME" "$INSTALL_SERVICE_PATH"

# 3. Install default configuration file if it doesn't exist
if [ ! -f "$INSTALL_CONFIG_PATH" ]; then
    echo "Creating default configuration file at $INSTALL_CONFIG_PATH..."
    cat > "$INSTALL_CONFIG_PATH" <<EOF
# GPU NUMA Optimizer Configuration

# Use SMT/HT sibling cores (true/false)
#UseHt=true

# Run in daemon mode (true/false)
#DaemonMode=false

# Seconds to wait between process checks in daemon mode
#SleepInterval=10

# Strict memory policy (true/false)
# true = use 'membind' (fails if node full), false = use 'preferred'
#StrictMem=false

# Pin GPU IRQs to the local NUMA node (true/false)
#OptimizeIrqs=true

# Include "nearby" NUMA nodes in addition to the closest one (true/false)
#IncludeNearby=true

# Maximum distance value from 'numactl -H' to consider a node "nearby"
#MaxDist=11

# Only optimize processes identified as games or high-perf apps (true/false)
#OnlyGaming=true

# Skip system-level tuning (sysctl, etc.) (true/false)
#SkipSystemTune=false

# Force max PCIe performance (disable ASPM/Runtime PM) (true/false)
#MaxPerf=true

# Dry-run mode (true/false)
#DryRun=false

# Drop from root to the logged-in user after system tuning (true/false)
#DropPrivs=true

# Maximum number of lines to keep in the all-time optimization log
#MaxAllTimeLogLines=10000

# Default GPU index to optimize
#GpuIndex=0

# Interval between periodic summary reports (seconds)
#SummaryInterval=1800

# Stop summary messages after inactivity (seconds)
#SummarySilenceTimeout=7200

# Number of log lines before repeating the table header
#HeaderInterval=20

# Create per-command default configuration files
#AutoGenConfig=true

# Also optimize PipeWire-related processes (true/false)
#TunePipeWire=true

# GPU Index to target (from lspci)
#GpuIndex=0

# Nice value for optimized processes (-20 to 19, "" to skip)
#ReniceValue=-10

# Ionice class/value (e.g., "best-effort:0", "" to skip)
#IoniceValue=best-effort:0

# SystemTune Original values
EOF
else
    echo "Configuration file $INSTALL_CONFIG_PATH already exists. Skipping..."
fi

# 4. Reload systemd and handle the service
echo "Reloading systemd daemon..."
systemctl daemon-reload

# Check if service is already active
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo "Restarting existing $SERVICE_NAME..."
    systemctl restart "$SERVICE_NAME"
else
    echo "Enabling and starting $SERVICE_NAME..."
    systemctl enable "$SERVICE_NAME"
    systemctl start "$SERVICE_NAME"
fi

echo "----------------------------------------"
echo "Installation/Update complete!"
echo "Status of $SERVICE_NAME:"
systemctl status "$SERVICE_NAME" --no-pager -l || true
