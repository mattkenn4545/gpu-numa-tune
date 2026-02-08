#!/bin/bash

# ==============================================================================
# GPU NUMA Optimizer
# ==============================================================================
# Purpose:
#   Optimizes gaming and high-performance application performance by aligning
#   processes with the system's NUMA (Non-Uniform Memory Access) topology.
#
# Mechanism:
#   1. Detects the NUMA node closest to a specified GPU (default: index 0).
#   2. Optionally identifies "nearby" NUMA nodes based on hardware distance.
#   3. Tunes system parameters (sysctl, CPU governors) for low latency.
#   4. Monitors for processes using the GPU (render nodes/NVIDIA devices).
#   5. Applies CPU affinity (pinning) and memory policies (membind/preferred)
#      to ensure the process runs on the optimal CPU cores and memory nodes.
#   6. Migrates existing memory pages to the target nodes.
#
# Requirements:
#   - Linux with NUMA support
#   - Utilities: lspci, fuser, taskset, numactl, migratepages, setpriv
#
# Usage:
#   sudo ./gpu_optimize.sh [options] [gpu_index]
# ==============================================================================

# --- Configuration ---
UseHt=true                   # Use SMT/HT sibling cores (Hyper-Threading)
DaemonMode=false             # If true, monitor and optimize processes continuously
SleepInterval=10             # Seconds to wait between process checks in daemon mode
StrictMem=false              # true = use 'membind' (fails if node full), false = use 'preferred'
IncludeNearby=true           # If true, include "nearby" NUMA nodes in addition to the closest one
MaxDist=11                   # Maximum distance value from 'numactl -H' to consider a node "nearby"
OnlyGaming=true              # If true, only optimize processes identified as games or high-perf apps
SkipSystemTune=false         # If true, do not attempt to modify sysctl or CPU governors
OptimizeIrqs=true            # If true, pin GPU IRQs to the local NUMA node
MaxPerf=true                 # If true, force PCIe device and ASPM to maximum performance
DryRun=false                 # If true, log intended changes but do not apply them
DropPrivs=true               # If true, drop from root to the logged-in user after system tuning
AutoGenConfig=true           # If true, create per-command default configuration files
TunePipeWire=true            # If true, also optimize PipeWire-related processes
ReniceValue="-10"            # Nice value for optimized processes (-20 to 19, "" to skip)
IoniceValue="best-effort:0"  # Ionice class/value (e.g., "best-effort:0", "" to skip)
MaxAllTimeLogLines=10000     # Maximum number of lines to keep in the all-time optimization log
GpuIndexArg=0                # Default GPU index
SystemConfig=${MOCK_CONFIG:-"/etc/gpu-numa-tune.conf"}
LocalConfigPath=".config/gpu-numa-tune"

# Load configuration from files
load_config() {
    local config_files=(
        "$SystemConfig"
        "$HOME/${LocalConfigPath}/gpu-numa-tune.conf"
        "$(pwd)/gpu-numa-tune.conf"
    )

    for file in "${config_files[@]}"; do
        [ -f "$file" ] && parse_config_file "$file"
    done
}

# Helper to parse a single configuration file
parse_config_file() {
    local file="$1"
    [ -f "$file" ] || return 0
    while IFS='=' read -r key value || [ -n "$key" ]; do
        # Ignore comments and empty lines
        [[ "$key" =~ ^[[:space:]]*#.*$ ]] && continue
        [[ -z "$key" ]] && continue

        # Remove leading/trailing whitespace from key and value
        # Using Bash pattern substitution for performance
        key="${key//[[:space:]]/}"
        value="${value#"${value%%[![:space:]]*}"}"
        value="${value%"${value##*[![:space:]]}"}"
        # Remove trailing comments from value if any
        value="${value%%#*}"
        value="${value%"${value##*[![:space:]]}"}"

        case "$key" in
            UseHt) UseHt="$value" ;;
            DaemonMode) DaemonMode="$value" ;;
            SleepInterval) SleepInterval="$value" ;;
            StrictMem) StrictMem="$value" ;;
            IncludeNearby) IncludeNearby="$value" ;;
            MaxDist) MaxDist="$value" ;;
            OnlyGaming) OnlyGaming="$value" ;;
            OptimizeIrqs) OptimizeIrqs="$value" ;;
            SkipSystemTune) SkipSystemTune="$value" ;;
            MaxPerf) MaxPerf="$value" ;;
            DryRun) DryRun="$value" ;;
            DropPrivs) DropPrivs="$value" ;;
            TunePipeWire) TunePipeWire="$value" ;;
            AutoGenConfig) AutoGenConfig="$value" ;;
            ReniceValue) ReniceValue="$value" ;;
            IoniceValue) IoniceValue="$value" ;;
            MaxAllTimeLogLines) MaxAllTimeLogLines="$value" ;;
            GpuIndex) GpuIndexArg="$value" ;;
            SummaryInterval) SummaryInterval="$value" ;;
            SummarySilenceTimeout) SummarySilenceTimeout="$value" ;;
            HeaderInterval) HeaderInterval="$value" ;;
        esac
    done < "$file"
}

# Load per-process configuration based on simplified_cmd
load_process_config() {
    local simplified_cmd="$1"
    local config_name="${simplified_cmd}.conf"

    local config_files=()

    # 1. Global per-process config
    config_files+=("/etc/gpu-numa-tune/${config_name}")

    # 2. User per-process config
    if [ -n "$TargetUser" ]; then
        local target_home=$(getent passwd "$TargetUser" | cut -d: -f6)
        [ -n "$target_home" ] && config_files+=("${target_home}/${LocalConfigPath}/${config_name}")
    fi
    config_files+=("$HOME/${LocalConfigPath}/${config_name}")

    # 3. Current directory
    config_files+=("$(pwd)/${config_name}")

    for file in "${config_files[@]}"; do
        if [ -f "$file" ]; then
            parse_config_file "$file"
        fi
    done
}

# Creates a default configuration file for a process if it doesn't exist
create_process_config() {
    local simplified_cmd="$1"
    local config_name="${simplified_cmd}.conf"
    local config_dir=""
    local config_path=""

    if [ -n "$TargetUser" ]; then
        local target_home=$(getent passwd "$TargetUser" | cut -d: -f6)
        [ -n "$target_home" ] && config_dir="${target_home}/${LocalConfigPath}"
    else
        config_dir="$HOME/${LocalConfigPath}"
    fi
    config_path="${config_dir}/${config_name}"

    local existing_config=""
    if [ -f "$config_path" ]; then
        existing_config="$config_path"
    fi

    if [ -z "$existing_config" ]; then
        if [ "$DryRun" = false ]; then
            mkdir -p "$config_dir" 2>/dev/null
            cat > "$config_path" <<EOF
UseHt=${GlobalUseHt:-$UseHt}
IncludeNearby=${GlobalIncludeNearby:-$IncludeNearby}
MaxDist=${GlobalMaxDist:-$MaxDist}
StrictMem=${GlobalStrictMem:-$StrictMem}
ReniceValue=${GlobalReniceValue:-$ReniceValue}
IoniceValue=${GlobalIoniceValue:-$IoniceValue}
EOF
            # If we're root but target user exists, ensure they own the file
            if [ "$EUID" -eq 0 ] && [ -n "$TargetUser" ]; then
                chown -R "$TargetUser:$TargetGid" "$config_dir" 2>/dev/null
            fi
            log "Created default config for $simplified_cmd at $config_path"
        else
            log "Dry run: Would create default config for $simplified_cmd at $config_path"
        fi
    fi
}

# State Tracking
SystemTuned=""                    # Tracks if system optimizations are currently applied (true/false/empty)
declare -A OptimizedPidsMap       # Map of PID -> Unix timestamp of when it was first optimized
declare -A AlwaysOptimizePidsMap  # Map of PID -> 1 for processes that are optimized but will not trigger system management
declare -A NonGamingPidsMap       # Map of PID -> Unix timestamp of when it was identified as non-gaming
declare -A BatchedProcInfoMap     # Map of PID -> "PPID|COMM|ARGS"
TotalOptimizedCount=0             # Total number of unique processes optimized since script start
PerformanceWarningsCount=0        # Total number of 20s+ loop warnings since script start
LastOptimizedCount=-1             # Number of optimized processes in the last check
AllTimeFile=""                    # Path to the all-time tracking file
LifetimeOptimizedCount=0          # Total number of unique processes optimized across all runs
LastSummaryTime=$(date +%s)       # Timestamp of the last periodic summary report
LastOptimizationTime=$(date +%s)  # Timestamp of the last successful optimization
SummarySilenced=false             # True if we have silenced periodic summaries due to inactivity
SummaryInterval=1800              # Interval between periodic summary reports (seconds)
SummarySilenceTimeout=7200        # Stop summary messages after 2 hours of inactivity
LogLineCount=9999                 # Counter to track when to re-print table headers
HeaderInterval=20                 # Number of log lines before repeating the table header

# Notification Buffer
declare -a PendingOptimizations # Queue of optimization events waiting to be displayed to the user

# Process Environment
OriginalArgs=("$@")          # Store original CLI arguments for privilege-dropped re-execution
TargetUser=""                # Username of the logged-in graphical user
TargetUid=""                 # UID of the TargetUser
TargetGid=""                 # GID of the TargetUser

# --- Utilities & Logging ---

# Global mock prefix for testing
SYSFS_PREFIX="${SYSFS_PREFIX:-}"
PROC_PREFIX="${PROC_PREFIX:-}"
DEV_PREFIX="${DEV_PREFIX:-}"

# State for PCIe warning to ensure it's only logged once per summary
PcieWarningLogged=false

# Displays a formatted table row for process optimization status
status_log() {
    local pid="$1"
    local exe="$2"
    local cmd="$3"
    local affinity="$4"
    local status="$5"
    local overrides="$6"

    if [ "$LogLineCount" -ge "$HeaderInterval" ]; then
        LogLineCount=0

        # Print table header
        echo "--------------------------------------------------------------------------------------------------------------------------------"
        status_log "PID" "EXE" "CMD" "AFFINITY" "STATUS" "OVERRIDES"
        echo "--------------------------------------------------------------------------------------------------------------------------------"
    fi

    [ -z "$pid" ] && return

    printf "%-10s | %-16s | %-20s | %-18s | %-25s | %-25s\n" "$pid" "$exe" "$cmd" "$affinity" "$status" "$overrides"
    ((LogLineCount++))
}

# Standard log function for informational exceptions to normal operation.
log() {
    echo "[LOG] $(date "+%H:%M:%S") - $1"
}

# Standard error function for critical failures.
error() {
    echo "[ERROR] $(date "+%H:%M:%S") - $1" >&2
}

usage() {
    echo "Usage: $0 [options] [gpu_index]"
    echo
    echo "Options:"
    echo "  -p, --physical-only  Use only physical CPU cores (skip SMT/HT siblings)"
    echo "  -d, --daemon         Run in daemon mode (check every $SleepInterval seconds)"
    echo "  -s, --strict         Strict memory policy (OOM risk, but guaranteed local memory)"
    echo "  -l, --local-only     Use only the GPU's local NUMA node (ignore nearby nodes)"
    echo "  -a, --all-gpu-procs  Optimize ALL processes using the GPU (not just games)"
    echo "  -x, --no-tune        Skip system-level tuning (sysctl, etc.)"
    echo "  --no-irq             Skip GPU IRQ optimization"
    echo "  -f, --max-perf       Force max PCIe performance (disable ASPM/Runtime PM)"
    echo "  -n, --dry-run        Dry-run mode (don't apply any changes)"
    echo "  -c, --no-config      Do not automatically create per-command local configs"
    echo "  --no-pipewire        Do not optimize PipeWire processes"
    echo "  -k, --no-drop        Keep root privileges (do not drop to user)"
    echo "  --comm-pipe <path>   Use a specific path for the communication pipe"
    echo "  -m, --max-log-lines  Maximum all-time log lines (default: $MaxAllTimeLogLines)"
    echo "  -h, --help           Show this help message"
    echo
    echo "Arguments:"
    echo "  gpu_index            Index of the GPU from lspci (default: 0)"
    exit 0
}

# Send desktop notification using notify-send.
notify_user() {
    local title="$1"
    local message="$2"
    local icon="${3:-dialog-information}"

    if command -v notify-send >/dev/null 2>&1; then
        # Ensure DBUS and XDG vars are set for notify-send to work in a daemon context
        if [ -n "$TargetUid" ]; then
            env DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$TargetUid/bus" \
                XDG_RUNTIME_DIR="/run/user/$TargetUid" \
                notify-send -a "GPU NUMA Optimizer" -i "$icon" "$title" "$message" >/dev/null 2>&1
        else
            notify-send -a "GPU NUMA Optimizer" -i "$icon" "$title" "$message" >/dev/null 2>&1
        fi
    fi
}

# Processes and displays queued notifications.
# This function sorts the queued optimizations by process RSS size and
# combines them into a single desktop notification to avoid user annoyance.
flush_notifications() {
    [ ${#PendingOptimizations[@]} -eq 0 ] && return

    # Sort pending optimizations by RSS size descending
    local sorted_pending=()
    if [ ${#PendingOptimizations[@]} -gt 1 ]; then
        local IFS_BACKUP=$IFS
        IFS=$'\n'
        # shellcheck disable=SC2207
        sorted_pending=($(printf "%s\n" "${PendingOptimizations[@]}" | sort -t'|' -k6,6rn))
        IFS=$IFS_BACKUP
    else
        sorted_pending=("${PendingOptimizations[@]}")
    fi

    local count=${#sorted_pending[@]}
    local primary_data="${sorted_pending[0]}"

    IFS='|' read -r p_pid p_comm p_simplified p_status p_nodes p_rss <<< "$primary_data"

    local title=""
    local message=""
    local icon="dialog-information"

    if [ "$count" -eq 1 ]; then
        title="$p_comm (PID: $p_pid): $p_status"
        message="$p_simplified\n\nCPU affinity set and memory handled on Nodes $p_nodes"
        [[ "$p_status" == *"FAILED"* || "$p_status" == *"FULL"* ]] && icon="dialog-warning"
    else
        title="Optimized $p_simplified ($p_comm) + $((count - 1)) additional processes"
        message="$p_status on Nodes $p_nodes \n\n"
        message+="Additional processes: \n"

        for (( i=1; i < count; i++ )); do
            IFS='|' read -r o_pid o_comm o_simplified o_status o_nodes o_rss <<< "${sorted_pending[$i]}"
            message+="- $o_simplified ($o_comm): $o_status\n"
            [[ "$o_status" == *"FAILED"* || "$o_status" == *"FULL"* ]] && icon="dialog-warning"
        done

        [[ "$p_status" == *"FAILED"* || "$p_status" == *"FULL"* ]] && icon="dialog-warning"
    fi

    notify_user "$title" "$message" "$icon"

    # Clear the buffer
    PendingOptimizations=()
}

# --- System Discovery & Hardware Info ---

# Checks if the GPU is running at its maximum PCIe link speed and width.
# Also checks if Resizable BAR is enabled and
#   PCIe Max Payload Size (MPS) and Max Read Request Size (MRRS) is appropriate
# Logs a warning if it's not.
check_pcie_speed() {
    [ "$PcieWarningLogged" = true ] && return
    local device_sys_dir="$SYSFS_PREFIX/sys/bus/pci/devices/$PciAddr"
    [ ! -d "$device_sys_dir" ] && return

    local cur_speed=$(cat "$device_sys_dir/current_link_speed" 2>/dev/null)
    local max_speed=$(cat "$device_sys_dir/max_link_speed" 2>/dev/null)
    local cur_width=$(cat "$device_sys_dir/current_link_width" 2>/dev/null)
    local max_width=$(cat "$device_sys_dir/max_link_width" 2>/dev/null)

    local warned=false
    if [ -n "$cur_speed" ] && [ -n "$max_speed" ] && [ "$cur_speed" != "$max_speed" ]; then
        log "WARNING: GPU is not running at max PCIe speed! Current: $cur_speed, Max: $max_speed"
        warned=true
    fi

    if [ -n "$cur_width" ] && [ -n "$max_width" ] && [ "$cur_width" != "$max_width" ]; then
        log "WARNING: GPU is not running at max PCIe width! Current: x$cur_width, Max: x$max_width"
        warned=true
    fi

    # Check Resizable BAR
    if command -v lspci >/dev/null 2>&1; then
        local lspci_vv=$(lspci -vv -s "$PciAddr" 2>/dev/null)
        if echo "$lspci_vv" | grep -q "Capabilities: .* Resizable BAR"; then
            # Capability found, check if it is enabled (has a BAR that is resized)
            local lspci_s=$(lspci -s "$PciAddr" 2>/dev/null)
            # Better check: nvidia-smi if it's NVIDIA
            if [[ "$lspci_s" == *"NVIDIA"* ]] && command -v nvidia-smi >/dev/null 2>&1; then
                if nvidia-smi -q -i "$PciAddr" 2>/dev/null | grep -q "Resizable BAR.*Disabled"; then
                    log "WARNING: Resizable BAR is disabled in NVIDIA settings/BIOS!"
                    warned=true
                fi
            elif [[ "$lspci_s" == *"Advanced Micro Devices"* ]]; then
                 # For AMD, check if BAR size is 256MB while larger sizes are supported
                 if echo "$lspci_vv" | grep -A 10 "Resizable BAR" | grep -q "current: 256MB" && \
                    echo "$lspci_vv" | grep -A 10 "Resizable BAR" | grep -qE "1GB|2GB|4GB|8GB|16GB"; then
                     log "WARNING: Resizable BAR is only 256MB! (Likely disabled in BIOS)"
                     warned=true
                 fi
            fi
        fi

        # Check PCIe Max Payload Size (MPS) and Max Read Request Size (MRRS)
        # DevCap: MaxPayload 256 bytes, ...
        # DevCtl: ... MaxPayload 128 bytes, MaxReadReq 512 bytes
        local dev_cap=$(echo "$lspci_vv" | grep -A 2 "DevCap:" | grep "MaxPayload" | head -n 1)
        local dev_ctl=$(echo "$lspci_vv" | grep -A 2 "DevCtl:" | grep "MaxPayload" | head -n 1)

        if [ -n "$dev_cap" ] && [ -n "$dev_ctl" ]; then
            local max_payload_cap=$(echo "$dev_cap" | sed -n 's/.*MaxPayload \([0-9]*\) bytes.*/\1/p')
            local max_payload_cur=$(echo "$dev_ctl" | sed -n 's/.*MaxPayload \([0-9]*\) bytes.*/\1/p')
            local max_read_req=$(echo "$dev_ctl" | sed -n 's/.*MaxReadReq \([0-9]*\) bytes.*/\1/p')

            if [ -n "$max_payload_cap" ] && [ -n "$max_payload_cur" ] && [ "$max_payload_cur" -lt "$max_payload_cap" ]; then
                log "WARNING: PCIe Max Payload Size (MPS) is suboptimal! Current: ${max_payload_cur}B, Capable: ${max_payload_cap}B"
                warned=true
            fi

            # Typically MaxReadReq should be at least as large as MaxPayload, and often larger (e.g. 512B or 4096B)
            # 128B is usually too low for high performance GPUs
            if [ -n "$max_read_req" ] && [ "$max_read_req" -le 128 ]; then
                 log "WARNING: PCIe Max Read Request Size (MRRS) is low (${max_read_req}B)! This may limit performance."
                 warned=true
            fi
        fi
    fi

    [ "$warned" = true ] && PcieWarningLogged=true
}

# Identifies the GPU's PCI address based on the provided index.
detect_gpu() {
    # Preferred: GPUs with active render nodes (DRM/DRI)
    # This identifies modern GPUs by checking /dev/dri/renderD* devices.
    mapfile -t active_gpus < <(
        for d in "$DEV_PREFIX"/dev/dri/renderD*; do
            [ -e "$d" ] || continue
            # Get PCI address from sysfs for this render node
            # Example: /dev/dri/renderD128 -> /sys/class/drm/renderD128/device
            pci_path=$(readlink -f "$SYSFS_PREFIX/sys/class/drm/$(basename "$d")/device" 2>/dev/null)
            if [[ "$pci_path" =~ ([0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-9a-fA-F])$ ]]; then
                echo "${BASH_REMATCH[1]}"
            fi
        done | sort -u
    )

    # Fallback/Additional: Known GPU vendors if no render nodes are active or detected.
    # We look for NVIDIA, AMD, and Intel VGA or 3D controllers.
    mapfile -t vendor_gpus < <(lspci -D | grep -iE "NVIDIA|Advanced Micro Devices|Intel Corporation" | grep -iE "VGA|3D" | awk '{print $1}')

    # Merge both detection methods and deduplicate results.
    mapfile -t all_gpu_pci < <(printf "%s\n" "${active_gpus[@]}" "${vendor_gpus[@]}" | grep -v "^$" | sort -u)

    if [ "${#all_gpu_pci[@]}" -eq 0 ]; then
        # Last resort: Any device reported by lspci as VGA or 3D.
        mapfile -t all_gpu_pci < <(lspci -D | grep -iE 'vga|3d' | awk '{print $1}')
    fi

    if [ "${#all_gpu_pci[@]}" -eq 0 ]; then
        error "No GPU (VGA/3D) devices detected."
        exit 1
    fi

    if [ "$GpuIndexArg" -ge "${#all_gpu_pci[@]}" ]; then
        error "GPU index $GpuIndexArg not found (Found ${#all_gpu_pci[@]} GPUs)."
        exit 1
    fi

    PciAddr="${all_gpu_pci[$GpuIndexArg]}"

    if [ -z "$PciAddr" ]; then
        error "Could not determine PCI address for GPU index $GpuIndexArg."
        exit 1
    fi
}

# Determines NUMA nodes and CPU list associated with the GPU
# Can be called with specific settings to recalculate for a process.
discover_resources() {
    local l_include_nearby="${1:-$IncludeNearby}"
    local l_max_dist="${2:-$MaxDist}"

    local device_sys_dir="$SYSFS_PREFIX/sys/bus/pci/devices/$PciAddr"
    if [ ! -d "$device_sys_dir" ]; then
        error "PCI device directory $device_sys_dir not found."
        exit 1
    fi

    NumaNodeId=$(cat "$device_sys_dir/numa_node" 2>/dev/null || echo -1)
    RawCpuList=$(cat "$device_sys_dir/local_cpulist" 2>/dev/null || echo "")

    NearbyNodeIds="$NumaNodeId"
    if [ "$l_include_nearby" = true ]; then
        NearbyNodeIds=$(get_nearby_nodes "$NumaNodeId" "$l_max_dist")
    fi

    if [ -n "$NearbyNodeIds" ] && [ "$NearbyNodeIds" != "$NumaNodeId" ] && [ "$NearbyNodeIds" != "-1" ]; then
        RawCpuList=$(get_nodes_cpulist "$NearbyNodeIds")
    fi

    if [ -z "$RawCpuList" ] || [ "$RawCpuList" == " " ]; then
        log "Warning: Could not determine local CPU list for GPU. Falling back to all CPUs."
        RawCpuList=$(cat "$SYSFS_PREFIX/sys/devices/system/cpu/online" 2>/dev/null)
    fi
}

# Returns a comma-separated list of NUMA nodes within MaxDist of the target node.
# This uses 'numactl --hardware' to determine the relative distance between nodes.
get_nearby_nodes() {
    local target_node=$1
    local l_max_dist=$2
    local nearby=()

    if [ "$target_node" -lt 0 ]; then
        echo ""
        return
    fi

    if command -v numactl >/dev/null 2>&1; then
        local distances=$(numactl --hardware | awk -v node="$target_node" '$1 == node":" {for(i=2; i<=NF; i++) print $i}')
        if [ -n "$distances" ]; then
            local i=0
            while read -r dist; do
                if [ "$dist" -le "$l_max_dist" ]; then
                    nearby+=("$i")
                fi
                ((i++))
            done <<< "$distances"
            echo "${nearby[*]}" | tr ' ' ','
            return
        fi
    fi

    echo "$target_node"
}

# Returns a space-separated list of IRQs associated with the detected GPU
get_gpu_irqs() {
    local irqs=()
    local device_sys_dir="$SYSFS_PREFIX/sys/bus/pci/devices/$PciAddr"

    # 1. Primary IRQ
    if [ -f "$device_sys_dir/irq" ]; then
        local primary_irq=$(cat "$device_sys_dir/irq")
        [ "$primary_irq" -gt 0 ] && irqs+=("$primary_irq")
    fi

    # 2. MSI/MSI-X IRQs
    if [ -d "$device_sys_dir/msi_irqs" ]; then
        for irq in "$device_sys_dir/msi_irqs/"*; do
            [ -e "$irq" ] || continue
            local b_irq=$(basename "$irq")
            [[ "$b_irq" =~ ^[0-9]+$ ]] && irqs+=("$b_irq")
        done
    fi

    # Deduplicate and return
    local result=$(echo "${irqs[@]}" | tr ' ' '\n' | sort -un | xargs echo)
    [ -n "$DEBUG" ] && echo "DEBUG: get_gpu_irqs found: $result" >&2
    echo "$result"
}

# Combines CPU lists from multiple NUMA nodes
get_nodes_cpulist() {
    local nodes=$1
    local combined=""
    IFS=',' read -ra node_list <<< "$nodes"
    for node in "${node_list[@]}"; do
        local cpulist=$(cat "$SYSFS_PREFIX/sys/devices/system/node/node$node/cpulist" 2>/dev/null)
        [ -n "$cpulist" ] && combined+="$cpulist,"
    done
    echo "${combined%,}"
}

get_node_free_kb() {
    # shellcheck disable=SC2086
    local free_kb=$(grep -i "Node $1 MemFree" "$SYSFS_PREFIX/sys/devices/system/node/node$1/meminfo" 2>/dev/null | awk '{print $4}')
    echo "${free_kb:-0}"
}

get_node_total_mb() {
    # shellcheck disable=SC2086
    local total_kb=$(grep -i "Node $1 MemTotal" "$SYSFS_PREFIX/sys/devices/system/node/node$1/meminfo" 2>/dev/null | awk '{print $4}')
    echo "$(( ${total_kb:-0} / 1024 ))"
}

get_node_used_mb() {
    # shellcheck disable=SC2086
    local used_kb=$(grep -i "Node $1 MemUsed" "$SYSFS_PREFIX/sys/devices/system/node/node$1/meminfo" 2>/dev/null | awk '{print $4}')
    echo "$(( ${used_kb:-0} / 1024 ))"
}

detect_target_user() {
    # Try to find a logged-in user that isn't root
    local detected_user=""

    while [ -z "$detected_user" ]; do
        # Use loginctl list-users to find non-root users
        # Format: UID USER LINGERING STATE
        local user_list=$(loginctl list-users --no-legend 2>/dev/null | awk '$2 != "root" && $4 == "active" {print $2}')

        # Select the first non-root user found
        detected_user=$(echo "$user_list" | head -n 1)

        # Fallbacks if no user found via loginctl
        if [ -z "$detected_user" ]; then
            detected_user=$(who | awk '($2 ~ /:[0-9]/) {print $1; exit}')
            [ -z "$detected_user" ] && detected_user="$SUDO_USER"
            [ -z "$detected_user" ] && [ "$EUID" -ne 0 ] && detected_user="$USER"
            [ "$detected_user" = "root" ] && detected_user=""
        fi

        if [ -n "$detected_user" ]; then
            TargetUser="$detected_user"
            TargetUid=$(id -u "$TargetUser")
            TargetGid=$(id -g "$TargetUser")
            return 0
        fi

        # If we are in daemon mode and haven't found a user yet, wait and try again.
        # This is important when starting at boot before any user has logged in.
        if [ "$DaemonMode" = true ]; then
            log "Waiting for a login session..."
            sleep 10
            detected_user="" # Reset for next loop
        else
            # Not in daemon mode, don't wait.
            return 1
        fi
    done
}

# --- CPU & Affinity Management ---

# Formats a list of numbers into sorted ranges (e.g., 1,2,3,5,6 -> 1-3,5-6)
format_range() {
    local input="$1"
    [ -z "$input" ] && return
    
    local sorted_nums
    sorted_nums=$(echo "$input" | tr ',' '\n' | sort -n | uniq | xargs echo)
    [ -z "$sorted_nums" ] && return

    local result=""
    local range_start=""
    local prev_num=""
    
    read -ra nums <<< "$sorted_nums"
    for num in "${nums[@]}"; do
        if [ -z "$prev_num" ]; then
            range_start="$num"
            prev_num="$num"
            continue
        fi
        
        if [ "$num" -eq "$((prev_num + 1))" ]; then
            prev_num="$num"
        else
            if [ "$range_start" -eq "$prev_num" ]; then
                result+="${range_start},"
            elif [ "$((range_start + 1))" -eq "$prev_num" ]; then
                result+="${range_start},${prev_num},"
            else
                result+="${range_start}-${prev_num},"
            fi
            range_start="$num"
            prev_num="$num"
        fi
    done
    
    # Add last group
    if [ "$range_start" -eq "$prev_num" ]; then
        result+="${range_start}"
    elif [ "$((range_start + 1))" -eq "$prev_num" ]; then
        result+="${range_start},${prev_num}"
    else
        result+="${range_start}-${prev_num}"
    fi
    
    echo "$result"
}

# Converts CPU list (e.g., 0-3,6) to a sorted, unique, comma-separated list
normalize_affinity() {
    # shellcheck disable=SC2162
    echo "$1" | tr ',' '\n' | while read r; do
        # shellcheck disable=SC2086
        if [[ $r == *-* ]]; then seq ${r%-*} ${r#*-}; else echo $r; fi
    done | sort -n | tr '\n' ',' | sed 's/,$//'
}

# Filters the CPU list based on UseHt configuration
# Can be called with specific settings to recalculate for a process.
filter_cpus() {
    local l_use_ht="${1:-$UseHt}"
    FinalCpuMask=""
    if [ "$l_use_ht" = true ]; then
        # If Hyper-Threading is allowed, use the full list of CPUs provided by the hardware
        FinalCpuMask="$RawCpuList"
    else
        # If physical-only mode is requested, we must filter out the HT/SMT siblings.
        # We iterate through the raw CPU list, which may contain ranges (e.g., 0-7,12).
        IFS=',' read -ra cpu_ranges <<< "$RawCpuList"
        for range in "${cpu_ranges[@]}"; do
            [ -z "$range" ] && continue

            # Expand ranges like '0-3' into '0 1 2 3'
            # shellcheck disable=SC2086
            [[ $range == *-* ]] && expanded_list=$(seq ${range%-*} ${range#*-}) || expanded_list=$range

            for cpu_id in $expanded_list; do
                # On Linux, thread siblings are listed in sysfs.
                # Usually, the first sibling in the list is the physical core.
                sibling_file="$SYSFS_PREFIX/sys/devices/system/cpu/cpu$cpu_id/topology/thread_siblings_list"
                if [ -f "$sibling_file" ]; then
                    # The file contains a comma or dash separated list of sibling IDs.
                    # We extract the first numeric ID to identify the "primary" core.
                    # shellcheck disable=SC2002
                    first_sibling=$(cat "$sibling_file" | cut -d',' -f1 | cut -d'-' -f1)

                    # If the current CPU ID matches the first sibling, it's a primary/physical core.
                    [[ "$cpu_id" -eq "$first_sibling" ]] && FinalCpuMask+="$cpu_id,"
                fi
            done
        done
        # Remove trailing comma
        FinalCpuMask=${FinalCpuMask%,}
    fi

    TargetNormalizedMask=$(normalize_affinity "$FinalCpuMask")
}

# --- Process Analysis & Filtering ---

# Extracts a simplified executable name for configuration lookups and notifications.
# Usage: get_simplified_cmd <pid> <proc_comm> <full_proc_cmd>
get_simplified_cmd() {
    local pid="$1"
    local proc_comm="$2"
    local full_proc_cmd="$3"
    local simplified_cmd=""

    if [[ "$full_proc_cmd" =~ \.[eE][xX][eE] ]]; then
        simplified_cmd=$(echo "$full_proc_cmd" | sed 's/\.[eE][xX][eE].*/.exe/i' | sed 's/.*[\\\/]//')
    elif [ "$full_proc_cmd" != "[Hidden or Exited]" ] && [ -n "$full_proc_cmd" ]; then
        simplified_cmd=$(echo "$full_proc_cmd" | awk '{print $1}' | sed 's/.*[\\\/]//')
    fi

    # Ensure simplified_cmd is not empty
    [ -z "$simplified_cmd" ] && simplified_cmd="$proc_comm"
    [ -z "$simplified_cmd" ] && simplified_cmd="Process $pid"

    echo "$simplified_cmd"
}

# Returns a comma-separated string of per-process configuration overrides
get_overrides() {
    local old_ht="$1"
    local old_nearby="$2"
    local old_dist="$3"
    local old_strict="$4"
    local old_renice="$5"
    local old_ionice="$6"

    local overrides=""
    [ "$UseHt" != "$old_ht" ] && overrides+="UseHt=$UseHt,"
    [ "$IncludeNearby" != "$old_nearby" ] && overrides+="IncludeNearby=$IncludeNearby,"
    [ "$MaxDist" != "$old_dist" ] && overrides+="MaxDist=$MaxDist,"
    [ "$StrictMem" != "$old_strict" ] && overrides+="StrictMem=$StrictMem,"
    [ "$ReniceValue" != "$old_renice" ] && overrides+="ReniceValue=$ReniceValue,"
    [ "$IoniceValue" != "$old_ionice" ] && overrides+="IoniceValue=$IoniceValue,"
    echo "${overrides%,}"
}

# Batch load process information into a global map to minimize ps forks.
batch_load_proc_info() {
    # Clear the existing map
    BatchedProcInfoMap=()

    # Capture pid, ppid, comm, and args in one go.
    # Using a while loop with read is generally more robust for parsing ps output.
    # We use a custom delimiter (if possible) or just rely on positional parsing.
    # ps -eo pid:10,ppid:10,comm:32,args
    # Note: comm might have spaces, but args definitely will.
    # Standard ps -eo pid,ppid,comm,args output:
    #   PID  PPID COMMAND         COMMAND
    while read -r l_pid l_ppid l_comm l_args; do
        [[ "$l_pid" =~ ^[0-9]+$ ]] || continue
        BatchedProcInfoMap["$l_pid"]="$l_ppid|$l_comm|$l_args"
    done < <(ps -eo pid,ppid,comm,args --no-headers 2>/dev/null | sed 's/^[[:space:]]*//')
}

# Determines if a PID should be optimized based on its environment and command line.
# This function applies several layers of heuristics to identify games:
# 1. Checks a blacklist of common desktop/system apps (browsers, shells, etc.).
# 2. Looks for UI/Utility markers in process arguments (e.g., Chromium's --type=renderer).
# 3. Searches for environment variables common to Steam, Proton, Lutris, and Heroic.
# 4. Checks for binary names containing '.exe', 'wine', 'proton', or 'Game'.
# 5. Inspects the parent process chain for known game launchers/runtimes.
is_gaming_process() {
    local pid="$1"

    [ "$OnlyGaming" = false ] && return 0

    # 0. Cache Check
    if [ -n "${NonGamingPidsMap[$pid]}" ]; then
        return 1
    fi

    local cached_info="${BatchedProcInfoMap[$pid]}"
    local proc_comm=""
    local proc_args=""
    local ppid=""

    if [ -n "$cached_info" ]; then
        IFS='|' read -r ppid proc_comm proc_args <<< "$cached_info"
    else
        # Fallback if not in cache (should not happen if batch_load_proc_info was called)
        proc_comm=$(ps -p "$pid" -o comm= 2>/dev/null)
        proc_args=$(ps -fp "$pid" -o args= 2>/dev/null)
        ppid=$(ps -p "$pid" -o ppid= 2>/dev/null | tr -d ' ')
    fi

    # 1. Known Blacklist
    case "$proc_comm" in
        Xorg|gnome-shell|kwin_wayland|sway|wayland|Xwayland) 
            NonGamingPidsMap["$pid"]=$(date +%s)
            return 1 
            ;;
        chrome|firefox|brave|msedge|opera|browser|chromium) 
            NonGamingPidsMap["$pid"]=$(date +%s)
            return 1 
            ;;
        steamwebhelper|Discord|slack|teams|obs|obs64|heroic|lutris|fossilize_repla) 
            NonGamingPidsMap["$pid"]=$(date +%s)
            return 1 
            ;;
    esac

    # 2. UI/Utility Heuristics
    local ui_regex="--type=(zygote|renderer|gpu-process|utility|extension-process|worker-process)"
    if [[ "$proc_args" =~ $ui_regex ]]; then
        NonGamingPidsMap["$pid"]=$(date +%s)
        return 1
    fi

    # 3. Environment Variable Markers (Steam, Proton, Lutris, etc.)
    if [ -r "$PROC_PREFIX/proc/$pid/environ" ]; then
        # Check for common game environment variables
        if tr '\0' '\n' < "$PROC_PREFIX/proc/$pid/environ" 2>/dev/null | grep -qE "^(STEAM_COMPAT_APP_ID|STEAM_GAME_ID|LUTRIS_GAME_ID|HEROIC_APP_NAME|PROTON_VER|WINEPREFIX)="; then
            return 0
        fi
    fi

    # 4. Binary Name Heuristics
    local binary_regex="\.exe|wine|proton|reaper|Game\.x86_64|UnityPlayer|UnrealEditor|Solaris|GZDoom"
    if [[ "$proc_args" =~ $binary_regex ]]; then
        return 0
    fi

    # 5. Parent Process Check
    for i in {1..3}; do
        [ -z "$ppid" ] || [ "$ppid" -lt 10 ] && break
        
        local p_cached_info="${BatchedProcInfoMap[$ppid]}"
        local p_comm=""
        local next_ppid=""

        if [ -n "$p_cached_info" ]; then
            IFS='|' read -r next_ppid p_comm _ <<< "$p_cached_info"
        else
            p_comm=$(ps -p "$ppid" -o comm= 2>/dev/null)
            next_ppid=$(ps -p "$ppid" -o ppid= 2>/dev/null | tr -d ' ')
        fi

        case "$p_comm" in
            steam|lutris|heroic|wine|wineserver) return 0 ;;
        esac
        ppid="$next_ppid"
    done

    # 6. PipeWire processes
    case "$proc_comm" in
        pipewire|pipewire-pulse|pipewire-media-session|wireplumber)
            return 0
            ;;
    esac

    NonGamingPidsMap["$pid"]=$(date +%s)
    return 1
}

# --- System Optimization & Tuning ---

# Persists original value of a system setting to the config file if not already present.
# This creates a "first encounter" record of the system state.
persist_original_value() {
    local key="$1"
    local value="$2"

    [ -z "$SystemConfig" ] && return
    
    # Check if key already exists in the config file
    if [ -f "$SystemConfig" ] && grep -qE "^[[:space:]]*${key}=" "$SystemConfig"; then
        return
    fi

    # Create directory if it doesn't exist
    local config_dir=$(dirname "$SystemConfig")
    if [ ! -d "$config_dir" ]; then
        if [ "$DryRun" = false ]; then
            mkdir -p "$config_dir" 2>/dev/null || return
        else
            return
        fi
    fi
    [ ! -w "$config_dir" ] && return

    # Extract the active value enclosed in brackets if present
    if [[ "$value" =~ \[([^\]]+)\] ]]; then
        value="${BASH_REMATCH[1]}"
    fi

    # Append the key=value pair to the config file
    if [ "$DryRun" = false ]; then
        # Ensure there is a newline if file is not empty and doesn't end with one
        if [ -s "$SystemConfig" ] && [ -n "$(tail -c 1 "$SystemConfig" 2>/dev/null)" ]; then
            echo "" >> "$SystemConfig"
        fi
        echo "${key}=${value}" >> "$SystemConfig"
    else
        printf "  [DRY] Persist %-24s = %-10s (Original Value)\n" "$key" "$value"
    fi
}

# Applies or reverts system-wide low-latency and NUMA-related optimizations (requires root)
system_manage_settings() {
    local action="$1" # "tune" or "restore"
    [ "$SkipSystemTune" = true ] && return 0

    # Determine effective EUID (allowing for mocking in tests)
    local eff_euid="${MOCK_EUID:-$EUID}"
    if [ "$eff_euid" -ne 0 ]; then
        if [ "$SystemTuned" == "" ]; then
            echo "------------------------------------------------------------------------------------------------"
            log "Notice: Not running as root..System-wide tuning skipped."
            echo "------------------------------------------------------------------------------------------------"
        fi
        return 1
    fi

    if [ "$action" = "restore" ]; then
        # Reload config to ensure we have the latest original values for restoration
        [ -f "$SystemConfig" ] && parse_config_file "$SystemConfig"
        [ ! -f "$SystemConfig" ] && {
            [ "$SystemTuned" = true ] && log "Warning: Restoration config $SystemConfig missing."
            return 1
        }
        echo "Restoring system to original state..."
    else
        echo "Applying system-wide optimizations..."
    fi

    # Helper to get the target value for a setting
    get_target_val() {
        local key="$1"
        local tune_val="$2"

        if [ "$action" = "tune" ]; then
            echo "$tune_val"
        else
            # action = restore
            grep "^${key}=" "$SystemConfig" 2>/dev/null | cut -d= -f2
        fi
    }

    # Helper for sysctl settings
    manage_sysctl() {
        local key="$1"
        local tune_val="$2"
        local label="$3"

        local target_val=$(get_target_val "$key" "$tune_val")
        [ -z "$target_val" ] && return 0

        if [ "$action" = "tune" ]; then
            local sys_path="$PROC_PREFIX/proc/sys/${key//./\/}"
            if [ -f "$sys_path" ] || sysctl "$key" >/dev/null 2>&1; then
                local current_val
                if [ -f "$sys_path" ]; then
                    current_val=$(cat "$sys_path")
                else
                    current_val=$(sysctl -n "$key" 2>/dev/null)
                fi
                persist_original_value "$key" "$current_val"
            else
                [ "$SystemTuned" == "" ] && printf "  [SKIP] %-28s (Not supported by kernel)\n" "$key"
                return 0
            fi
        fi

        if [ "$DryRun" = false ]; then
            SYSCTL_CALLED=true
            if sysctl -w "$key=$target_val" >/dev/null 2>&1; then
                [ "$SystemTuned" == "" ] && printf "  [OK] %-30s -> %-10s (%s)\n" "$key" "$target_val" "$label"
            else
                [ "$SystemTuned" == "" ] && printf "  [FAIL] %-28s -> %-10s (%s)\n" "$key" "$target_val" "$label"
            fi
        else
            [ "$SystemTuned" == "" ] && printf "  [DRY] %-29s -> %-10s (%s)\n" "$key" "$target_val" "$label"
        fi
    }

    # Helper for generic sysfs/file settings
    manage_setting() {
        local key="$1"
        local file_path="$2"
        local tune_val="$3"
        local label="$4"

        [ ! -f "$file_path" ] && return 0
        local target_val=$(get_target_val "$key" "$tune_val")
        [ -z "$target_val" ] && return 0

        if [ "$action" = "tune" ]; then
            local current_val=$(cat "$file_path" 2>/dev/null)
            persist_original_value "$key" "$current_val"
        fi

        if [ "$DryRun" = false ]; then
            if echo "$target_val" > "$file_path" 2>/dev/null; then
                [ "$SystemTuned" == "" ] && printf "  [OK] %-30s -> %-10s (%s)\n" "$key" "$target_val" "$label"
            else
                [ "$SystemTuned" == "" ] && printf "  [FAIL] %-28s -> %-10s (%s)\n" "$key" "$target_val" "$label"
            fi
        else
            [ "$SystemTuned" == "" ] && printf "  [DRY] %-29s -> %-10s (%s)\n" "$key" "$target_val" "$label"
        fi
    }

    # Helper for managing systemd services. Does not persist state or use SystemConfig as whether the service is present is sufficient
    manage_service() {
        local service_name="$1"
        local service="${service_name}.service"

        if [ "$DryRun" = false ]; then
          if ! systemctl list-unit-files "$service" >/dev/null 2>&1; then
              return 0
          fi
        fi

        if [ "$action" = "tune" ]; then
            if [ "$DryRun" = false ]; then
                if systemctl stop "$service" 2>/dev/null; then
                    [ "$SystemTuned" == "" ] && printf "  [OK] %-30s -> %-10s (%s)\n" "$service" "stopped" "Latency"
                else
                    [ "$SystemTuned" == "" ] && printf "  [FAIL] %-28s -> %-10s (%s)\n" "$service" "stop failed" "Latency"
                fi
            else
                [ "$SystemTuned" == "" ] && printf "  [DRY] %-29s -> %-10s (%s)\n" "$service" "stop" "Latency"
            fi
        else
            # action = restore
            if [ "$DryRun" = false ]; then
                if systemctl start "$service" 2>/dev/null; then
                    [ "$SystemTuned" == "" ] && printf "  [OK] %-30s -> %-10s (%s)\n" "$service" "started" "Restore"
                else
                    [ "$SystemTuned" == "" ] && printf "  [FAIL] %-28s -> %-10s (%s)\n" "$service" "start failed" "Restore"
                fi
            else
                [ "$SystemTuned" == "" ] && printf "  [DRY] %-29s -> %-10s (%s)\n" "$service" "start" "Restore"
            fi
        fi
    }

    # Helper for IRQ affinity
    manage_irq_affinity() {
        [ "$OptimizeIrqs" != true ] && return 0

        local tuned_irqs=()
        local failed_irqs=()
        local dry_irqs=()

        for irq in $(get_gpu_irqs); do
            local key="irq_${irq}_affinity"
            local affinity_file="$PROC_PREFIX/proc/irq/$irq/smp_affinity_list"
            [ -f "$affinity_file" ] || continue

            if [ "$DryRun" = false ]; then
                if echo "$TargetNormalizedMask" > "$affinity_file" 2>/dev/null; then
                    tuned_irqs+=("$irq")
                else
                    failed_irqs+=("$irq")
                fi
            else
                dry_irqs+=("$irq")
            fi
        done

        if [ "$SystemTuned" == "" ]; then
            if [ ${#tuned_irqs[@]} -gt 0 ]; then
                local irq_list=$(format_range "$(echo "${tuned_irqs[@]}" | tr ' ' ',')")
                local label="IRQ Affinity"
                [ "$action" = "restore" ] && label="IRQ Restore"
                printf "  [OK] %-30s -> %-10s (%s)\n" "IRQs Optimized" "$irq_list" "$label"
            fi
            if [ ${#failed_irqs[@]} -gt 0 ]; then
                local irq_list=$(format_range "$(echo "${failed_irqs[@]}" | tr ' ' ',')")
                printf "  [FAIL] %-28s -> %-10s (%s)\n" "IRQs Failed" "$irq_list" "IRQ Affinity"
            fi
            if [ ${#dry_irqs[@]} -gt 0 ]; then
                local irq_list=$(format_range "$(echo "${dry_irqs[@]}" | tr ' ' ',')")
                printf "  [DRY] %-29s -> %-10s (%s)\n" "IRQs Optimized" "$irq_list" "IRQ Affinity"
            fi
        fi
    }

    # Apply/Restore Sysctl Settings
    manage_sysctl "vm.max_map_count" "2147483647" "Memory Mapping"
    manage_sysctl "kernel.numa_balancing" "0" "NUMA Contention"
    manage_sysctl "kernel.split_lock_mitigate" "0" "Execution Latency"
    manage_sysctl "kernel.sched_migration_cost_ns" "5000000" "Scheduler"
    manage_sysctl "net.core.netdev_max_backlog" "5000" "Network"
    manage_sysctl "net.core.busy_read" "50" "Network Latency"
    manage_sysctl "net.core.busy_poll" "50" "Network Latency"
    manage_sysctl "vm.stat_interval" "10" "Jitter Reduction"
    manage_sysctl "kernel.nmi_watchdog" "0" "Interrupt Latency"
    manage_service irqbalance
    manage_service numad
    manage_irq_affinity

    # PCIe Max Performance
    if [ "$MaxPerf" = true ] || [ "$action" = "restore" ]; then
        manage_setting "pcie_aspm_policy" "$SYSFS_PREFIX/sys/module/pcie_aspm/parameters/policy" "performance" "PCIe Perf"
        manage_setting "gpu_runtime_pm_control" "$SYSFS_PREFIX/sys/bus/pci/devices/$PciAddr/power/control" "on" "PCIe Perf"
        manage_setting "gpu_l1_aspm" "$SYSFS_PREFIX/sys/bus/pci/devices/$PciAddr/link/l1_aspm" "0" "PCIe Perf"
        manage_setting "gpu_clkpm" "$SYSFS_PREFIX/sys/bus/pci/devices/$PciAddr/link/clkpm" "0" "PCIe Perf"
    fi

    # CPU Scaling Governor
    if [ -d "$SYSFS_PREFIX/sys/devices/system/cpu/cpufreq" ]; then
        local target_gov=$(get_target_val "cpu_governor" "performance")
        if [ -n "$target_gov" ]; then
            if [ "$action" = "tune" ]; then
                local first_gov_file=$(find "$SYSFS_PREFIX/sys/devices/system/cpu/cpu"*/cpufreq/scaling_governor -type f -print -quit 2>/dev/null)
                if [ -n "$first_gov_file" ] && [ -f "$first_gov_file" ]; then
                    persist_original_value "cpu_governor" "$(cat "$first_gov_file")"
                fi
            fi
            if [ "$DryRun" = false ]; then
                local gov_applied=false
                for gov in "$SYSFS_PREFIX"/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
                    if [ -f "$gov" ]; then
                        echo "$target_gov" > "$gov" 2>/dev/null && gov_applied=true
                    fi
                done
                if [ "$gov_applied" = true ]; then
                    [ "$SystemTuned" == "" ] && printf "  [OK] %-30s -> %-10s (%s)\n" "cpu_governor" "$target_gov" "Power/Perf"
                fi
            else
                [ "$SystemTuned" == "" ] && printf "  [DRY] %-29s -> %-10s (%s)\n" "cpu_governor" "$target_gov" "Power/Perf"
            fi
        fi
    fi

    if [ "$action" = "tune" ]; then
        [ "$SystemTuned" == "" ] && echo "--> System tuning complete."
        [ "$SystemTuned" == "" ] && echo "------------------------------------------------------------------------------------------------"
      SystemTuned=true
    else
      SystemTuned=false
    fi

    return 0
}

# Triggers system-wide action (tune/restore)
trigger_system_management() {
    local action="$1" # "tune" or "restore"
    local target_state
    local pipe_msg

    if [ "$action" = "tune" ]; then
        [ "$SystemTuned" = true ] && return 0
        target_state=true
        pipe_msg="TUNE"
    else
        [ "$SystemTuned" = false ] && return 0
        target_state=false
        pipe_msg="RESTORE"
    fi

    local eff_euid="${MOCK_EUID:-$EUID}"
    if [ "$eff_euid" -eq 0 ]; then
        if system_manage_settings "$action"; then
            SystemTuned="$target_state"
        fi
    elif [ -n "$CommPipe" ] && [ -p "$CommPipe" ]; then
        if echo "$pipe_msg" > "$CommPipe" 2>/dev/null; then
            SystemTuned="$target_state"
        fi
    fi
}


# --- Core Logic & Execution ---

# Applies affinity, memory policies, and priority to a PID
apply_process_policies() {
    local pid="$1"
    local final_cpu_mask="$2"
    local nearby_nodes="$3"
    local numa_node_id="$4"
    local strict_mem="$5"
    local renice_val="$6"
    local ionice_val="$7"

    [ "$DryRun" = true ] && return 0

    # 1. CPU Affinity
    taskset -pc "$final_cpu_mask" "$pid" > /dev/null 2>&1

    # 2. Memory Policy
    local target_nodes="${nearby_nodes:-$numa_node_id}"
    if [ "$strict_mem" = true ]; then
        numactl --membind="$target_nodes" -p "$pid" > /dev/null 2>&1
    else
        # Preferred policy: try multiple nodes if available, fallback to single
        if [[ "$target_nodes" == *","* ]]; then
            if ! numactl --preferred-many="$target_nodes" -p "$pid" > /dev/null 2>&1; then
                 numactl --preferred="${target_nodes%%,*}" -p "$pid" > /dev/null 2>&1
            fi
        else
            numactl --preferred="$target_nodes" -p "$pid" > /dev/null 2>&1
        fi
    fi

    # 3. Process Priority (Renice)
    if [ -n "$renice_val" ]; then
        renice -n "$renice_val" -p "$pid" > /dev/null 2>&1
    fi

    # 4. IO Priority (Ionice)
    if [ -n "$ionice_val" ]; then
        if [[ "$ionice_val" == *":"* ]]; then
            local class="${ionice_val%%:*}"
            local classdata="${ionice_val##*:}"
            case "$class" in
                idle) ionice -c 3 -p "$pid" > /dev/null 2>&1 ;;
                best-effort) ionice -c 2 -n "$classdata" -p "$pid" > /dev/null 2>&1 ;;
                realtime) ionice -c 1 -n "$classdata" -p "$pid" > /dev/null 2>&1 ;;
            esac
        else
            case "$ionice_val" in
                idle) ionice -c 3 -p "$pid" > /dev/null 2>&1 ;;
                best-effort) ionice -c 2 -p "$pid" > /dev/null 2>&1 ;;
                realtime) ionice -c 1 -p "$pid" > /dev/null 2>&1 ;;
            esac
        fi
    fi
}

# Attempts to migrate memory pages of a process to the target nodes
# Returns:
# 0 = Success (Moved)
# 1 = Invalid target
# 2 = Migration command failed
# 3 = Target node full (Not enough free RAM)
# 5 = Process too old (Skipped to prevent late-game stutter)
migrate_process_memory() {
    local pid="$1"
    local target_nodes="$2"
    local rss_kb="$3"
    # Safety buffer to ensure we don't fill the node completely (default 512MB)
    local safety_margin_kb="${4:-524288}"

    # --- CONFIGURATION ---
    # Max age in seconds (120s = 2 minutes).
    # If a process has been running longer than this, we assume gameplay
    # has started and migration would cause unacceptable stutter.
    local max_migration_age=120
    # ---------------------

    [[ "$target_nodes" == "-1" || -z "$target_nodes" ]] && return 1

    # 1. Process Age Check
    # ps -o etimes gives elapsed time in seconds since the process started
    local proc_age=$(ps -p "$pid" -o etimes= 2>/dev/null | tr -d ' ')

    # Verify we got a valid integer
    if [[ "$proc_age" =~ ^[0-9]+$ ]]; then
        if [ "$proc_age" -gt "$max_migration_age" ]; then
            # Return code 5: Process is too old to safely migrate
            return 5
        fi
    fi

    # 2. Free Memory Check
    local free_kb=0
    IFS=',' read -ra node_list <<< "$target_nodes"
    for node in "${node_list[@]}"; do
        free_kb=$((free_kb + $(get_node_free_kb "$node")))
    done

    # Only migrate if there's enough free memory (RSS + Safety Margin)
    if [ "$free_kb" -gt $((rss_kb + safety_margin_kb)) ]; then
        if [ "$DryRun" = false ]; then
            if migratepages "$pid" all "$target_nodes" > /dev/null 2>&1; then
                return 0 # Success
            else
                return 2 # Failed
            fi
        else
            return 0 # Dry run success
        fi
    fi

    return 3 # Node full
}

# Standardizes process information extraction
get_proc_info() {
    local pid="$1"
    local cached_info="${BatchedProcInfoMap[$pid]}"
    local proc_comm=""
    local full_proc_cmd=""

    if [ -n "$cached_info" ]; then
        # cached_info is "ppid|comm|args"
        IFS='|' read -r _ proc_comm full_proc_cmd <<< "$cached_info"
    else
        proc_comm=$(ps -p "$pid" -o comm= 2>/dev/null)
        full_proc_cmd=$(ps -fp "$pid" -o args= 2>/dev/null | tail -n 1)
    fi

    [ -z "$full_proc_cmd" ] && full_proc_cmd="[Hidden or Exited]"
    local simplified_cmd=$(get_simplified_cmd "$pid" "$proc_comm" "$full_proc_cmd")
    local raw_affinity=$(taskset -pc "$pid" 2>/dev/null | awk -F': ' '{print $2}')
    echo "$proc_comm|$full_proc_cmd|$simplified_cmd|$raw_affinity"
}

# Main optimization loop: identifies GPU users and applies policies
run_optimization() {
    # Batch load process info to minimize forks in the loop
    batch_load_proc_info

    # Periodic cleanup of non-gaming cache to handle PID reuse
    local now=$(date +%s)
    for pid in "${!NonGamingPidsMap[@]}"; do
        if [ ! -d "$PROC_PREFIX/proc/$pid" ] || [ $((now - NonGamingPidsMap[$pid])) -gt 3600 ]; then
            unset "NonGamingPidsMap[$pid]"
        fi
    done

    # Cross-vendor PID detection (Render nodes and NVIDIA devices)
    local gpu_pids=$(fuser /dev/dri/renderD* /dev/nvidia* 2>/dev/null | tr ' ' '\n' | sort -u)

    # Detect processes that should always be optimized but should not result in system-wide tuning
    local always_optimize_pids=()
    if [ "$TunePipeWire" = true ]; then
        # pgrep -d' ' is a standard way to get a space-separated list of PIDs
        local p_pids=$(pgrep -f "pipewire|pipewire-pulse|pipewire-media-session|wireplumber" 2>/dev/null)
        if [ -n "$p_pids" ]; then
            always_optimize_pids+=($p_pids)
        fi
    fi

    local target_pids=$(echo -e "$gpu_pids\n${always_optimize_pids[*]}" | sort -u)

    for pid in $target_pids; do
        [[ -z "$pid" ]] && continue
        if [ "$pid" -lt 100 ] || [ ! -d "$PROC_PREFIX/proc/$pid" ]; then continue; fi

        for apid in "${always_optimize_pids[@]}"; do
            if [ "$apid" == "$pid" ]; then
                AlwaysOptimizePidsMap[$pid]=1
            fi
        done

        # Only optimize processes owned by the current user (unless root)
        if [ "$EUID" -ne 0 ] && [ ! -O "$PROC_PREFIX/proc/$pid" ]; then
            continue
        fi

        if ! is_gaming_process "$pid"; then continue; fi

        IFS='|' read -r proc_comm full_proc_cmd simplified_cmd raw_current_affinity <<< "$(get_proc_info "$pid")"

        # Load per-process configuration (overrides global settings)
        # Using a subshell to calculate process-specific settings without polluting globals
        local proc_settings=$(
            # Subshell starts here
            load_process_config "$simplified_cmd"

            local l_FinalCpuMask="$FinalCpuMask"
            local l_TargetNormalizedMask="$TargetNormalizedMask"
            local l_NearbyNodeIds="$NearbyNodeIds"
            local l_NumaNodeId="$NumaNodeId"
            local l_StrictMem="$StrictMem"
            local l_ReniceValue="$ReniceValue"
            local l_IoniceValue="$IoniceValue"

            if [ "$UseHt" != "$GlobalUseHt" ] || [ "$IncludeNearby" != "$GlobalIncludeNearby" ] || [ "$MaxDist" != "$GlobalMaxDist" ]; then
                # Recalculate resources if per-process config differs from global hardware discovery
                discover_resources "$IncludeNearby" "$MaxDist"
                filter_cpus "$UseHt"
                l_FinalCpuMask="$FinalCpuMask"
                l_TargetNormalizedMask="$TargetNormalizedMask"
                l_NearbyNodeIds="$NearbyNodeIds"
                l_NumaNodeId="$NumaNodeId"
            fi

            local overrides=$(get_overrides "$GlobalUseHt" "$GlobalIncludeNearby" "$GlobalMaxDist" "$GlobalStrictMem" "$GlobalReniceValue" "$GlobalIoniceValue")
            echo "$l_FinalCpuMask|$l_TargetNormalizedMask|$l_NearbyNodeIds|$l_NumaNodeId|$l_StrictMem|$l_ReniceValue|$l_IoniceValue|$overrides"
        )

        IFS='|' read -r l_FinalCpuMask l_TargetNormalizedMask l_NearbyNodeIds l_NumaNodeId l_StrictMem l_ReniceValue l_IoniceValue overrides <<< "$proc_settings"

        [ -z "$raw_current_affinity" ] && continue
        local current_normalized_mask=$(normalize_affinity "$raw_current_affinity")

        # We optimize if the mask doesn't match OR if we haven't tracked this PID as optimized yet
        # (to ensure memory policies and priorities are applied at least once)
        if [ "$current_normalized_mask" != "$l_TargetNormalizedMask" ] || [ -z "${OptimizedPidsMap[$pid]}" ]; then
            # Optimization required
            apply_process_policies "$pid" "$l_TargetNormalizedMask" "$l_NearbyNodeIds" "$l_NumaNodeId" "$l_StrictMem" "$l_ReniceValue" "$l_IoniceValue"

            local process_rss_kb=$(awk '/VmRSS/ {print $2}' "$PROC_PREFIX/proc/$pid/status" 2>/dev/null || echo 0)
            local target_nodes="${l_NearbyNodeIds:-$l_NumaNodeId}"

            local status_msg="OPTIMIZED"
            local skip_lifetime_optimized_count=false
            if migrate_process_memory "$pid" "$target_nodes" "$process_rss_kb"; then
                [ "$target_nodes" != "-1" ] && status_msg="OPTIMIZED & MOVED"
            else
                local m_res=$?
                [ "$m_res" -eq 2 ] && status_msg="OPTIMIZED (MOVE FAILED)"
                [ "$m_res" -eq 3 ] && status_msg="OPTIMIZED (NODE FULL)"
                [ "$m_res" -eq 5 ] && status_msg="OPTIMIZED (AGED PROCESS)" && skip_lifetime_optimized_count=true
            fi

            if [ "$DryRun" = true ]; then
                [[ "$status_msg" == *"MOVED"* ]] && status_msg="WOULD MOVE" || status_msg="DRY RUN ($status_msg)"
            fi

            # Queue for notification
            PendingOptimizations+=("$pid|$proc_comm|$simplified_cmd|$status_msg|$target_nodes|$process_rss_kb")
            status_log "$pid" "$proc_comm" "$simplified_cmd" "$(format_range "$l_TargetNormalizedMask")" "$status_msg" "$overrides"

            if [ -z "${OptimizedPidsMap[$pid]}" ] && [ "$skip_lifetime_optimized_count" = false ]; then
                ((TotalOptimizedCount++))
                ((LifetimeOptimizedCount++))
                LastOptimizationTime=$(date +%s)
                SummarySilenced=false

                if [ "$DryRun" = false ] && [ -n "$AllTimeFile" ]; then
                    # Log entry format: TIMESTAMP | PID | COMM | CMD | STATUS | NODES
                    printf "%-19s | %-8s | %-16s | %-20s | %-22s | %-8s\n" \
                        "$(date "+%Y-%m-%d %H:%M:%S")" "$pid" "$proc_comm" "$simplified_cmd" "$status_msg" "$target_nodes" >> "$AllTimeFile" 2>/dev/null
                    trim_all_time_log

                    if [ "$AutoGenConfig" = true ]; then
                        create_process_config "$simplified_cmd"
                    fi
                fi
            fi
            OptimizedPidsMap[$pid]=$(date +%s)
        fi

        # Restore globals for next process in the loop
    done

    if [ $((${#OptimizedPidsMap[@]} - ${#AlwaysOptimizePidsMap[@]})) -gt 0 ]; then
        trigger_system_management "tune"
    fi
}

# Periodically prints a summary of optimized processes
summarize_optimizations() {
    local force_summary=${1:-false}
    local now=$(date +%s)

    # First, cleanup dead processes to get an accurate count
    local always_optimized_count=0
    for pid in "${!OptimizedPidsMap[@]}"; do
        if [ ! -d "$PROC_PREFIX/proc/$pid" ]; then
            unset "OptimizedPidsMap[$pid]"
            unset "AlwaysOptimizePidsMap[$pid]"
        else
          # Count only processes that are not always optimized for system management purposes
          if [ -n "${AlwaysOptimizePidsMap[$pid]}" ]; then
              ((always_optimized_count++))
          fi
        fi
    done

    local current_optimized_count=${#OptimizedPidsMap[@]}
    current_optimized_count=$((current_optimized_count - always_optimized_count))

    # Trigger summary if forced, interval passed, or if we just dropped to zero optimized processes
    local should_summarize=false
    if [ "$force_summary" = true ] || [ $((now - LastSummaryTime)) -ge "$SummaryInterval" ]; then
        should_summarize=true
    elif [ "$LastOptimizedCount" -gt 0 ] && [ "$current_optimized_count" -eq 0 ]; then
        should_summarize=true
    fi

    LastOptimizedCount=$current_optimized_count

    local summary_msg="$((current_optimized_count + always_optimized_count)) processes currently optimized (${current_optimized_count} triggering tune)"
    if [ "$current_optimized_count" -eq 0 ]; then
        trigger_system_management "restore"
    fi

    if [ "$should_summarize" = true ]; then
        if [ "$force_summary" = false ] && [ $((now - LastOptimizationTime)) -ge "$SummarySilenceTimeout" ]; then
            if [ "$SummarySilenced" = false ]; then
                echo "------------------------------------------------------------------------------------------------"
                echo "No processes optimized in $((SummarySilenceTimeout / 3600)) hours. Silencing periodic summaries."
                echo "Monitoring continues; summaries will resume if a qualifying process is detected."
                echo "------------------------------------------------------------------------------------------------"
                SummarySilenced=true
            fi
            LastSummaryTime=$now
            return
        fi

        status_log "$TotalOptimizedCount procs" "since startup" "" "$LifetimeOptimizedCount all time" "OPTIMIZING" "$summary_msg"

        if [ "$PerformanceWarningsCount" -gt 0 ]; then
            log "Notice: $PerformanceWarningsCount performance warnings (20s+ loop) recorded since startup."
        fi

        PcieWarningLogged=false
        if [ "$current_optimized_count" -gt 0 ]; then
            check_pcie_speed
        fi

        # Sort PIDs numerically for consistent output
        local sorted_pids=$(echo "${!OptimizedPidsMap[@]}" | tr ' ' '\n' | sort -n)

        for pid in $sorted_pids; do
            # Batch load might be stale if we are in a long summary, but usually summary is fast.
            # We ensure we have info for these PIDs.
            if [ -z "${BatchedProcInfoMap[$pid]}" ]; then
                 batch_load_proc_info
            fi

            IFS='|' read -r proc_comm full_proc_cmd simplified_cmd raw_current_affinity <<< "$(get_proc_info "$pid")"

            # Load per-process configuration to find overrides for summary
            local overrides=$(
                load_process_config "$simplified_cmd"
                get_overrides "$GlobalUseHt" "$GlobalIncludeNearby" "$GlobalMaxDist" "$GlobalStrictMem" "$GlobalReniceValue" "$GlobalIoniceValue"
            )

            status_log "$pid" "$proc_comm" "$simplified_cmd" "$raw_current_affinity" "OPTIMIZED $(date -d "@${OptimizedPidsMap[$pid]}" "+%H:%M %D")" "$overrides"
        done

        LastSummaryTime=$now
    fi
}

# --- CLI & Startup ---

# Loads the all-time optimization count from the user's home directory.
load_all_time_stats() {
    local target_home=""
    if [ -n "$TargetUser" ]; then
        target_home=$(getent passwd "$TargetUser" | cut -d: -f6)
    fi
    [ -z "$target_home" ] && target_home="$HOME"

    if [ -n "$target_home" ]; then
        AllTimeFile="${target_home}/${LocalConfigPath}/optimizations.log"
        if [ -f "$AllTimeFile" ]; then
            LifetimeOptimizedCount=$(wc -l < "$AllTimeFile" 2>/dev/null || echo 0)
            # Ensure it's a number
            [[ "$LifetimeOptimizedCount" =~ ^[0-9]+$ ]] || LifetimeOptimizedCount=0
        fi
    fi
}

# Trims the all-time optimization log if it exceeds the maximum allowed lines.
# It uses a 50-line buffer to minimize full-file rewrites.
trim_all_time_log() {
    [ -z "$AllTimeFile" ] || [ ! -f "$AllTimeFile" ] && return

    local current_lines=$(wc -l < "$AllTimeFile" 2>/dev/null || echo 0)
    # Only trim if we exceed the limit by more than 50 lines to reduce IO
    if [ "$current_lines" -gt $((MaxAllTimeLogLines + 50)) ]; then
        local temp_file="${AllTimeFile}.tmp"
        if tail -n "$MaxAllTimeLogLines" "$AllTimeFile" > "$temp_file" 2>/dev/null; then
            mv "$temp_file" "$AllTimeFile"
        else
            rm -f "$temp_file"
        fi
    fi
}

# Parses command-line arguments and sets configuration variables
parse_args() {
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            -p|--physical-only) UseHt=false; shift ;;
            -d|--daemon) DaemonMode=true; shift ;;
            -s|--strict) StrictMem=true; shift ;;
            -l|--local-only) IncludeNearby=false; shift ;;
            -a|--all-gpu-procs) OnlyGaming=false; shift ;;
            -x|--no-tune) SkipSystemTune=true; shift ;;
            --no-irq) OptimizeIrqs=false; shift ;;
            -f|--max-perf) MaxPerf=true; shift ;;
            -n|--dry-run) DryRun=true; shift ;;
            -c|--no-config) AutoGenConfig=false; shift ;;
            --no-pipewire) TunePipeWire=false; shift ;;
            -k|--no-drop) DropPrivs=false; shift ;;
            --comm-pipe) CommPipe=$2; shift 2 ;;
            -m|--max-log-lines)
                if [[ "$2" =~ ^[0-9]+$ ]]; then
                    MaxAllTimeLogLines=$2; shift 2
                else
                    error "--max-log-lines requires a numeric argument."
                    exit 1
                fi
                ;;
            -h|--help) usage ;;
            -*) error "Unknown option: $1" ; usage ;;
            *)
                if [[ "$1" =~ ^[0-9]+$ ]]; then
                    GpuIndexArg=$1; shift
                else
                    error "GPU index must be a numeric value: $1"
                    exit 1
                fi
                ;;
        esac
    done
}

# Ensures all required external utilities are installed
check_dependencies() {
    local deps=("lspci" "fuser" "taskset" "numactl" "migratepages" "awk" "ps" "notify-send" "setpriv")
    PATH="$PATH:/usr/sbin:/sbin"
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            if [ "$cmd" = "notify-send" ] || [ "$cmd" = "setpriv" ]; then
                log "Warning: '$cmd' not found. Desktop notifications or privilege dropping may be limited."
            else
                error "Required command '$cmd' not found."
                exit 1
            fi
        fi
    done
}

# Prints hardware and configuration summary at startup
print_banner() {
    local mem_policy_label=$([ "$StrictMem" = true ] && echo "Strict (OOM Risk)" || echo "Preferred (Safe)")

    echo "------------------------------------------------------------------------------------------------"
    echo "GPU MODEL        :$(lspci -s "$PciAddr" | cut -d: -f3) ($PciAddr)"

    if [ "$NumaNodeId" -ge 0 ]; then
        if [ "$IncludeNearby" = true ] && [ -n "$NearbyNodeIds" ] && [ "$NearbyNodeIds" != "-1" ]; then
            echo "NUMA NODES       : $NearbyNodeIds (Nearby Max Distance $MaxDist)"
            IFS=',' read -ra nodes <<< "$NearbyNodeIds"
            for node in "${nodes[@]}"; do
               echo "NODE $node SIZE      : $(get_node_total_mb "$node") MB"
            done
        else
            echo "NUMA NODE        : $NumaNodeId (Local Only)"
            echo "NUMA NODE SIZE   : $(get_node_total_mb "$NumaNodeId") MB"
        fi
    fi

    echo "CPU TARGETS      : $( [ "$UseHt" = true ] && echo "HT Allowed" || echo "Physical Only" ) ($FinalCpuMask)"
    echo "MEM POLICY       : $mem_policy_label"
    echo "PROCESS FILTER   : $( [ "$OnlyGaming" = true ] && echo "Gaming Only" || echo "All GPU Processes" )"
    echo "AUTOGEN CONFIG   : $( [ "$AutoGenConfig" = true ] && echo "Enabled" || echo "Disabled" )"
    echo "PCIe PERF        : $( [ "$MaxPerf" = true ] && echo "Max (ASPM Disabled)" || echo "Default" )"
    echo "DRY RUN MODE     : $( [ "$DryRun" = true ] && echo "ENABLED (No changes will be applied)" || echo "Disabled" )"
    echo "MODE             : $( [ "$DaemonMode" = true ] && echo "Daemon" || echo "Single-run" )"

    echo "--------------------------------------------------------------------------------------------------------------------------------"
    check_pcie_speed
    status_log
}

# --- Main Script Execution ---

# Entry point of the script. Handles initialization, privilege dropping,
# and enters the main daemon loop or performs a single-run optimization.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Load configuration from files first (system-wide, then user-specific, then local)
    load_config
    # Parse CLI arguments (they override configuration files)
    parse_args "$@"
    check_dependencies
    detect_target_user
    detect_gpu
    discover_resources
    filter_cpus
    system_manage_settings "tune"

    # Root-privileged parent loop
    if [ "$DropPrivs" = true ] && [ "$EUID" -eq 0 ] && [ -n "$TargetUser" ]; then
        echo "--> Starting root management process..."

        # Create a named pipe for child-to-parent communication
        CommPipe=$(mktemp -u)
        mkfifo "$CommPipe"
        # Set permissions so root can read/write and the target group can write
        chmod 660 "$CommPipe"

        # Parent stays root and waits for signals or pipe commands
        # Open FIFO for reading and writing to prevent 'read' from closing on EOF
        # We open it BEFORE changing ownership to avoid 'Permission denied'
        # when fs.protected_fifos=1 (root must open it while it owns it in /tmp)
        exec 3<> "$CommPipe"

        # Change group to target user's group so they can write to it
        chown "root:$TargetGid" "$CommPipe"

        # Signal handlers for the parent
        trap '[ -e "/dev/fd/3" ] && exec 3>&-; rm -f "$CommPipe"; system_manage_settings "restore"; exit 0' TERM INT QUIT

        # Fork the child process
        (
            echo "--> Dropping privileges to $TargetUser..."
            # Re-execute the script as the target user.
            # --no-tune: Skip system_tune in the child as it requires root.
            # --no-drop: Prevent infinite re-execution loops.
            setpriv --reuid="$TargetUid" --regid="$TargetGid" --init-groups -- "$0" "--no-tune" "--no-drop" "--comm-pipe" "$CommPipe" "${OriginalArgs[@]}"
            # When child exits, signal the parent to exit too
            kill -TERM "$$" 2>/dev/null
        ) &
        ChildPid=$!

        while [ -e "/dev/fd/3" ]; do
            if read -t 1 -r cmd <&3 2>/dev/null; then
                case "$cmd" in
                    TUNE) system_manage_settings "tune" ;;
                    RESTORE) system_manage_settings "restore" ;;
                    EXIT) break ;;
                esac
            fi

            # Check if child is still alive. If child is gone, exit.
            if ! kill -0 "$ChildPid" 2>/dev/null; then
                echo "--> Child process exited. Shutting down root manager."
                break
            fi
        done
        [ -e "/dev/fd/3" ] && exec 3>&-
        rm -f "$CommPipe"

        # Kill child process if it's still alive (e.g. if parent got SIGTERM)
        if kill -0 "$ChildPid" 2>/dev/null; then
            kill -TERM "$ChildPid" 2>/dev/null
            wait "$ChildPid" 2>/dev/null
        fi

        system_manage_settings "restore"
        exit 0
    fi

    # Everything below runs either as root (if DropPrivs=false)
    # or as the target user (if DropPrivs=true, in the child process).

    # Initialize maps
    declare -A BatchedProcInfoMap
    declare -A OptimizedPidsMap
    declare -A NonGamingPidsMap

    load_all_time_stats

    # Capture global configuration baseline for override detection
    GlobalUseHt="$UseHt"
    GlobalIncludeNearby="$IncludeNearby"
    GlobalMaxDist="$MaxDist"
    GlobalStrictMem="$StrictMem"
    GlobalReniceValue="$ReniceValue"
    GlobalIoniceValue="$IoniceValue"

    # Setup signal handlers for cleanup
    trap 'trigger_system_management "restore"; exit 0' TERM INT QUIT

    # If running as child, the parent might already be terminating us.
    # We should ensure we don't leave zombie processes if we have children.
    # (Though this script doesn't normally fork other long-running processes)

    print_banner
    summarize_optimizations true
    if [ "$DaemonMode" = true ]; then
        # Continuous monitoring loop
        while true; do
            loop_start=$(date +%s%N)
            run_optimization

            # Aggregate notifications to avoid spamming the user.
            # If optimizations were performed, wait a short while for related processes
            # (e.g., a game launcher starting the game engine) to appear.
            if [ ${#PendingOptimizations[@]} -gt 0 ]; then
                # Sleep to give launchers etc... time to get all processes started
                sleep "$SleepInterval" &
                wait $!
                # Run one more time to catch immediate followers
                run_optimization
                flush_notifications
            fi

            # Summarize optimizations performed in this loop
            summarize_optimizations

            loop_end=$(date +%s%N)
            duration_ns=$((loop_end - loop_start))
            duration_ms=$((duration_ns / 1000000))

            if [ "$duration_ms" -gt 20000 ]; then
                log "Warning: Daemon loop took ${duration_ms}ms (exceeding 20s warning threshold)"
                # Record that a performance warning occurred for the summary
                ((PerformanceWarningsCount++))
            fi

            sleep "$SleepInterval" &
            wait $!
        done
    else
        # Single-run mode
        run_optimization
        flush_notifications
        summarize_optimizations # Ensure restoration happens if needed
        echo "------------------------------------------------------------------------------------------------"
        echo "Optimization complete."
    fi
fi
