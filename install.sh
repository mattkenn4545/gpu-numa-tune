#!/bin/bash

# Simple installer/updater for gpu-numa-tune

set -e

# Configuration
BIN_NAME="gpu_optimize.sh"
SERVICE_NAME="gpu-numa-optimizer.service"
INSTALL_BIN_PATH="/usr/local/bin/$BIN_NAME"
INSTALL_SERVICE_PATH="/etc/systemd/system/$SERVICE_NAME"

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

# 3. Reload systemd and handle the service
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
