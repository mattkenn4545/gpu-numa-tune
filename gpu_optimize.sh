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
#   3. Tunes system parameters (sysctl, THP, CPU governors) for low latency.
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
MaxPerf=false                # If true, force PCIe device and ASPM to maximum performance
DryRun=false                 # If true, log intended changes but do not apply them
DropPrivs=true               # If true, drop from root to the logged-in user after system tuning
AutoGenConfig=true           # If true, create per-command default configuration files
MaxAllTimeLogLines=10000     # Maximum number of lines to keep in the all-time optimization log
GpuIndexArg=0                # Default GPU index
SystemConfig="/etc/gpu-numa-tune.conf"

# Load configuration from files
load_config() {
    local config_files=(
        "$SystemConfig"
        "$HOME/.config/gpu-numa-tune.conf"
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
        key=$(echo "$key" | tr -d '[:space:]')
        value=${value##[[:space:]]}
        value=${value%%[[:space:]]}
        # Remove trailing comments from value if any
        value=${value%%#*}
        value=${value%%[[:space:]]}
        
        case "$key" in
            UseHt) UseHt="$value" ;;
            DaemonMode) DaemonMode="$value" ;;
            SleepInterval) SleepInterval="$value" ;;
            StrictMem) StrictMem="$value" ;;
            IncludeNearby) IncludeNearby="$value" ;;
            MaxDist) MaxDist="$value" ;;
            OnlyGaming) OnlyGaming="$value" ;;
            SkipSystemTune) SkipSystemTune="$value" ;;
            MaxPerf) MaxPerf="$value" ;;
            DryRun) DryRun="$value" ;;
            DropPrivs) DropPrivs="$value" ;;
            AutoGenConfig) AutoGenConfig="$value" ;;
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
        [ -n "$target_home" ] && config_files+=("${target_home}/.config/gpu-numa-tune/${config_name}")
    fi
    config_files+=("$HOME/.config/gpu-numa-tune/${config_name}")

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
        [ -n "$target_home" ] && config_dir="${target_home}/.config/gpu-numa-tune"
    else
        config_dir="$HOME/.config/gpu-numa-tune"
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
SystemTuned=""               # Tracks if system optimizations are currently applied (true/false/empty)
declare -A OptimizedPidsMap  # Map of PID -> Unix timestamp of when it was first optimized
TotalOptimizedCount=0        # Total number of unique processes optimized since script start
LastOptimizedCount=-1        # Number of optimized processes in the last check
AllTimeFile=""               # Path to the all-time tracking file
LifetimeOptimizedCount=0     # Total number of unique processes optimized across all runs
LastSummaryTime=$(date +%s)  # Timestamp of the last periodic summary report
LastOptimizationTime=$(date +%s) # Timestamp of the last successful optimization
SummarySilenced=false        # True if we have silenced periodic summaries due to inactivity
SummaryInterval=1800         # Interval between periodic summary reports (seconds)
SummarySilenceTimeout=7200   # Stop summary messages after 2 hours of inactivity
LogLineCount=9999            # Counter to track when to re-print table headers
HeaderInterval=20            # Number of log lines before repeating the table header

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

        echo "--------------------------------------------------------------------------------------------------------------------------------"
        status_log "PID" "EXE" "CMD" "ORIG AFFINITY" "STATUS" "OVERRIDES"
        echo "--------------------------------------------------------------------------------------------------------------------------------"
    fi

    [ -z "$pid" ] && return

    printf "%-10s | %-16s | %-20s | %-18s | %-25s | %-25s\n" "$pid" "$exe" "$cmd" "$affinity" "$status" "$overrides"
    ((LogLineCount++))
}

# Logs messages to syslog in daemon mode, or stdout otherwise
log() {
    if [ "$DaemonMode" = true ]; then
        logger -t gpu-numa-tune "$1"
    else
        echo "$1"
    fi
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
    echo "  -f, --max-perf       Force max PCIe performance (disable ASPM/Runtime PM)"
    echo "  -n, --dry-run        Dry-run mode (don't apply any changes)"
    echo "  -c, --no-config      Do not automatically create per-command local configs"
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
        echo "Error: No GPU (VGA/3D) devices detected."
        exit 1
    fi

    if [ "$GpuIndexArg" -ge "${#all_gpu_pci[@]}" ]; then
        echo "Error: GPU index $GpuIndexArg not found (Found ${#all_gpu_pci[@]} GPUs)."
        exit 1
    fi

    PciAddr="${all_gpu_pci[$GpuIndexArg]}"

    if [ -z "$PciAddr" ]; then
        echo "Error: Could not determine PCI address for GPU index $GpuIndexArg."
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
        echo "Error: PCI device directory $device_sys_dir not found."
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
        echo "Warning: Could not determine local CPU list for GPU. Falling back to all CPUs."
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
    # Try to find the user running the graphical session
    local detected_user=""
    local user_list=$(loginctl list-sessions --no-legend 2>/dev/null | awk '{print $3}' | sort -u)

    for u in $user_list; do
        local sids=$(loginctl list-sessions --no-legend 2>/dev/null | awk -v u="$u" '$3==u {print $1}')
        for sid in $sids; do
            local type=$(loginctl show-session "$sid" -p Type --value 2>/dev/null)
            local state=$(loginctl show-session "$sid" -p State --value 2>/dev/null)
            if [[ "$type" =~ ^(x11|wayland)$ ]] && [ "$state" = "active" ]; then
                detected_user="$u"
                break 2
            fi
        done
    done

    # Fallbacks
    [ -z "$detected_user" ] && detected_user=$(who | awk '($2 ~ /:[0-9]/) {print $1; exit}')
    [ -z "$detected_user" ] && detected_user="$SUDO_USER"
    [ -z "$detected_user" ] && [ "$EUID" -ne 0 ] && detected_user="$USER"

    if [ -n "$detected_user" ] && [ "$detected_user" != "root" ]; then
        TargetUser="$detected_user"
        TargetUid=$(id -u "$TargetUser")
        TargetGid=$(id -g "$TargetUser")
    fi
}

# --- CPU & Affinity Management ---

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
    
    local overrides=""
    [ "$UseHt" != "$old_ht" ] && overrides+="UseHt=$UseHt,"
    [ "$IncludeNearby" != "$old_nearby" ] && overrides+="IncludeNearby=$IncludeNearby,"
    [ "$MaxDist" != "$old_dist" ] && overrides+="MaxDist=$MaxDist,"
    [ "$StrictMem" != "$old_strict" ] && overrides+="StrictMem=$StrictMem,"
    echo "${overrides%,}"
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

    # 1. Known Blacklist
    local proc_comm=$(ps -p "$pid" -o comm= 2>/dev/null)
    case "$proc_comm" in
        Xorg|gnome-shell|kwin_wayland|sway|wayland|Xwayland) return 1 ;;
        chrome|firefox|brave|msedge|opera|browser|chromium) return 1 ;;
        steamwebhelper|Discord|slack|teams|obs|obs64|heroic|lutris|fossilize_repla) return 1 ;;
    esac

    # 2. UI/Utility Heuristics
    local proc_args=$(ps -fp "$pid" -o args= 2>/dev/null)
    if echo "$proc_args" | grep -qiE -- "--type=(zygote|renderer|gpu-process|utility|extension-process|worker-process)"; then
        return 1
    fi

    # 3. Environment Variable Markers (Steam, Proton, Lutris, etc.)
    if [ -r "$PROC_PREFIX/proc/$pid/environ" ]; then
        if tr '\0' '\n' < "$PROC_PREFIX/proc/$pid/environ" 2>/dev/null | grep -qE "^(STEAM_COMPAT_APP_ID|STEAM_GAME_ID|LUTRIS_GAME_ID|HEROIC_APP_NAME|PROTON_VER|WINEPREFIX)="; then
            return 0
        fi
    fi

    # 4. Binary Name Heuristics
    if echo "$proc_args" | grep -qiE "\.exe|wine|proton|reaper|Game\.x86_64|UnityPlayer|UnrealEditor|Solaris|GZDoom"; then
        return 0
    fi

    # 5. Parent Process Check
    local ppid=$(ps -p "$pid" -o ppid= 2>/dev/null | tr -d ' ')
    for i in {1..3}; do
        [ -z "$ppid" ] || [ "$ppid" -lt 10 ] && break
        local p_comm=$(ps -p "$ppid" -o comm= 2>/dev/null)
        case "$p_comm" in
            steam|lutris|heroic|wine|wineserver) return 0 ;;
        esac
        ppid=$(ps -p "$ppid" -o ppid= 2>/dev/null | tr -d ' ')
    done

    return 1
}

# --- System Optimization & Tuning ---

# Persists original value of a system setting to the config file if not already present.
# This creates a "first encounter" record of the system state.
persist_original_value() {
    local key="$1"
    local value="$2"
    
    [ -z "$SystemConfig" ] && return
    [ ! -w "$(dirname "$SystemConfig")" ] && return
    
    # Extract the active value enclosed in brackets if present (e.g., for THP)
    if [[ "$value" =~ \[([^\]]+)\] ]]; then
        value="${BASH_REMATCH[1]}"
    fi
    
    # Check if key already exists in the config file
    if [ -f "$SystemConfig" ] && grep -qE "^[[:space:]]*${key}=" "$SystemConfig"; then
        return
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
            echo "WARNING: Not running as root. Latency tuning skipped."
            echo "------------------------------------------------------------------------------------------------"
        fi
        return 1
    fi

    if [ "$action" = "restore" ]; then
        # Reload config to ensure we have the latest original values
        [ -f "$SystemConfig" ] && parse_config_file "$SystemConfig"
        [ ! -f "$SystemConfig" ] && {
            [ "$SystemTuned" = true ] && echo "Warning: Restoration config $SystemConfig missing."
            return 1
        }
    else
        [ "$SystemTuned" == "" ] && echo "--> Root detected. Applying system-wide optimizations..."
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

    # PCIe Max Performance
    if [ "$MaxPerf" = true ] || [ "$action" = "restore" ]; then
        # 1. Global ASPM policy
        local policy_file="$SYSFS_PREFIX/sys/module/pcie_aspm/parameters/policy"
        if [ -f "$policy_file" ]; then
            local target_aspm=$(get_target_val "pcie_aspm_policy" "performance")
            if [ -n "$target_aspm" ]; then
                [ "$action" = "tune" ] && persist_original_value "pcie_aspm_policy" "$(cat "$policy_file" 2>/dev/null)"
                if [ "$DryRun" = false ]; then
                    echo "$target_aspm" > "$policy_file" 2>/dev/null
                    [ "$SystemTuned" == "" ] && printf "  [OK] %-30s -> %-10s (%s)\n" "pcie_aspm_policy" "$target_aspm" "PCIe Perf"
                else
                    [ "$SystemTuned" == "" ] && printf "  [DRY] %-29s -> %-10s (%s)\n" "pcie_aspm_policy" "$target_aspm" "PCIe Perf"
                fi
            fi
        fi

        # 2. GPU Runtime PM
        local rpm_file="$SYSFS_PREFIX/sys/bus/pci/devices/$PciAddr/power/control"
        if [ -f "$rpm_file" ]; then
            local target_rpm=$(get_target_val "gpu_runtime_pm_control" "on")
            if [ -n "$target_rpm" ]; then
                [ "$action" = "tune" ] && persist_original_value "gpu_runtime_pm_control" "$(cat "$rpm_file" 2>/dev/null)"
                if [ "$DryRun" = false ]; then
                    echo "$target_rpm" > "$rpm_file" 2>/dev/null
                    [ "$SystemTuned" == "" ] && printf "  [OK] %-30s -> %-10s (%s)\n" "gpu_runtime_pm" "$target_rpm" "PCIe Perf"
                else
                    [ "$SystemTuned" == "" ] && printf "  [DRY] %-29s -> %-10s (%s)\n" "gpu_runtime_pm" "$target_rpm" "PCIe Perf"
                fi
            fi
        fi

        # 3. GPU ASPM/Clock PM
        for link_name in "l1_aspm" "clkpm"; do
            local link_file="$SYSFS_PREFIX/sys/bus/pci/devices/$PciAddr/link/$link_name"
            if [ -f "$link_file" ]; then
                local target_val=$(get_target_val "gpu_$link_name" "0")
                if [ -n "$target_val" ]; then
                    [ "$action" = "tune" ] && persist_original_value "gpu_$link_name" "$(cat "$link_file" 2>/dev/null)"
                    local display_val="$target_val"
                    [ "$target_val" = "0" ] && [ "$action" = "tune" ] && display_val="disabled"
                    if [ "$DryRun" = false ]; then
                        echo "$target_val" > "$link_file" 2>/dev/null
                        [ "$SystemTuned" == "" ] && printf "  [OK] %-30s -> %-10s (%s)\n" "gpu_$link_name" "$display_val" "PCIe Perf"
                    else
                        [ "$SystemTuned" == "" ] && printf "  [DRY] %-29s -> %-10s (%s)\n" "gpu_$link_name" "$display_val" "PCIe Perf"
                    fi
                fi
            fi
        done
    fi

    # Transparent Hugepages (THP)
    manage_thp() {
        local key="$1"
        local path="$2"
        local tune_val="$3"
        local label="$4"

        if [ -f "$path" ]; then
            local target_val=$(get_target_val "$key" "$tune_val")
            if [ -n "$target_val" ]; then
                [ "$action" = "tune" ] && persist_original_value "$key" "$(cat "$path" 2>/dev/null)"
                if [ "$DryRun" = false ]; then
                    echo "$target_val" > "$path" 2>/dev/null
                    [ "$SystemTuned" == "" ] && printf "  [OK] %-30s -> %-10s (%s)\n" "$key" "$target_val" "$label"
                else
                    [ "$SystemTuned" == "" ] && printf "  [DRY] %-29s -> %-10s (%s)\n" "$key" "$target_val" "$label"
                fi
            fi
        fi
    }
    manage_thp "transparent_hugepage" "$SYSFS_PREFIX/sys/kernel/mm/transparent_hugepage/enabled" "never" "Latency"
    manage_thp "thp_defrag" "$SYSFS_PREFIX/sys/kernel/mm/transparent_hugepage/defrag" "never" "Latency"

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
        if pgrep -x numad >/dev/null 2>&1; then
            [ "$SystemTuned" == "" ] && echo "  [WARNING] numad daemon is running. This may contend with manual optimization."
            [ "$SystemTuned" == "" ] && echo "            Consider stopping it: 'sudo systemctl stop numad'"
        fi
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

# Main optimization loop: identifies GPU users and applies policies
run_optimization() {
    # Cross-vendor PID detection (Render nodes and NVIDIA devices)
    local gpu_pids=$(fuser /dev/dri/renderD* /dev/nvidia* 2>/dev/null | tr ' ' '\n' | sort -u)

    for pid in $gpu_pids; do
        [[ -z "$pid" ]] && continue
        if [ "$pid" -lt 100 ] || [ ! -d "$PROC_PREFIX/proc/$pid" ]; then continue; fi
        
        # Only optimize processes owned by the current user (unless root)
        if [ "$EUID" -ne 0 ] && [ ! -O "$PROC_PREFIX/proc/$pid" ]; then
            continue
        fi

        if ! is_gaming_process "$pid"; then continue; fi

        trigger_system_management "tune"

        local proc_comm=$(ps -p "$pid" -o comm=)
        local full_proc_cmd=$(ps -fp "$pid" -o args= | tail -n 1)
        [ -z "$full_proc_cmd" ] && full_proc_cmd="[Hidden or Exited]"

        # Extract a simplified executable name for configuration lookups and notifications
        local simplified_cmd=$(get_simplified_cmd "$pid" "$proc_comm" "$full_proc_cmd")

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

            if [ "$UseHt" != "$GlobalUseHt" ] || [ "$IncludeNearby" != "$GlobalIncludeNearby" ] || [ "$MaxDist" != "$GlobalMaxDist" ]; then
                discover_resources "$IncludeNearby" "$MaxDist"
                filter_cpus "$UseHt"
                l_FinalCpuMask="$FinalCpuMask"
                l_TargetNormalizedMask="$TargetNormalizedMask"
                l_NearbyNodeIds="$NearbyNodeIds"
                l_NumaNodeId="$NumaNodeId"
            fi
            
            local overrides=$(get_overrides "$GlobalUseHt" "$GlobalIncludeNearby" "$GlobalMaxDist" "$GlobalStrictMem")
            echo "$l_FinalCpuMask|$l_TargetNormalizedMask|$l_NearbyNodeIds|$l_NumaNodeId|$l_StrictMem|$overrides"
        )

        IFS='|' read -r l_FinalCpuMask l_TargetNormalizedMask l_NearbyNodeIds l_NumaNodeId l_StrictMem overrides <<< "$proc_settings"

        local raw_current_affinity=$(taskset -pc "$pid" 2>/dev/null | awk -F': ' '{print $2}')
        if [ -z "$raw_current_affinity" ]; then
             continue
        fi
        local current_normalized_mask=$(normalize_affinity "$raw_current_affinity")

        if [ "$current_normalized_mask" != "$l_TargetNormalizedMask" ]; then
            if [ "$DryRun" = false ]; then
                taskset -pc "$l_FinalCpuMask" "$pid" > /dev/null 2>&1

                if [ "$l_StrictMem" = true ]; then
                    numactl --membind="${l_NearbyNodeIds:-$l_NumaNodeId}" -p "$pid" > /dev/null 2>&1
                else
                    # Preferred policy: try multiple nodes if available, fallback to single
                    if [[ "$l_NearbyNodeIds" == *","* ]]; then
                        if ! numactl --preferred-many="$l_NearbyNodeIds" -p "$pid" > /dev/null 2>&1; then
                             numactl --preferred="${l_NearbyNodeIds%%,*}" -p "$pid" > /dev/null 2>&1
                        fi
                    else
                        numactl --preferred="${l_NearbyNodeIds:-$l_NumaNodeId}" -p "$pid" > /dev/null 2>&1
                    fi
                fi
            fi

            local process_rss_kb=$(awk '/VmRSS/ {print $2}' "$PROC_PREFIX/proc/$pid/status" 2>/dev/null || echo 0)
            local safety_margin_kb=524288

            # Determine memory availability on target nodes to decide if migration is safe.
            local free_kb=0
            if [ -n "$l_NearbyNodeIds" ] && [ "$l_NearbyNodeIds" != "-1" ]; then
                IFS=',' read -ra nodes <<< "$l_NearbyNodeIds"
                for node in "${nodes[@]}"; do
                    free_kb=$((free_kb + $(get_node_free_kb "$node")))
                done
            elif [[ "$l_NumaNodeId" =~ ^[0-9]+$ ]] && [ "$l_NumaNodeId" -ge 0 ]; then
                free_kb=$(get_node_free_kb "$l_NumaNodeId")
            else
                free_kb=0
            fi

            # Migrate pages if there's enough free memory (with a safety margin).
            local target_nodes="${l_NearbyNodeIds:-$l_NumaNodeId}"
            if [[ "$target_nodes" != "-1" ]] && [ "$free_kb" -gt $((process_rss_kb + safety_margin_kb)) ]; then
                if [ "$DryRun" = false ]; then
                    if migratepages "$pid" all "$target_nodes" > /dev/null 2>&1; then
                        status_msg="OPTIMIZED & MOVED"
                    else
                        status_msg="OPTIMIZED (MOVE FAILED)"
                    fi
                else
                    status_msg="WOULD MOVE"
                fi
            elif [[ "$target_nodes" == "-1" ]]; then
                # Optimized affinity but no target NUMA node for memory
                status_msg="OPTIMIZED"
            else
                # Not enough free memory on the target nodes to safely migrate pages
                status_msg="OPTIMIZED (NODE FULL)"
            fi

            if [ "$DryRun" = true ]; then
                status_msg="DRY RUN ($status_msg)"
            fi

            # Queue for notification
            PendingOptimizations+=("$pid|$proc_comm|$simplified_cmd|$status_msg|$target_nodes|$process_rss_kb")
            status_log "$pid" "$proc_comm" "$simplified_cmd" "$raw_current_affinity" "$status_msg" "$overrides"

            if [ -z "${OptimizedPidsMap[$pid]}" ]; then
                ((TotalOptimizedCount++))
                ((LifetimeOptimizedCount++))
                LastOptimizationTime=$(date +%s)
                SummarySilenced=false
                if [ "$AutoGenConfig" = true ]; then
                    create_process_config "$simplified_cmd"
                fi
                if [ "$DryRun" = false ] && [ -n "$AllTimeFile" ]; then
                    # Log entry format: TIMESTAMP | PID | COMM | CMD | STATUS | NODES
                    printf "%-19s | %-8s | %-16s | %-20s | %-22s | %-8s\n" \
                        "$(date "+%Y-%m-%d %H:%M:%S")" "$pid" "$proc_comm" "$simplified_cmd" "$status_msg" "$target_nodes" >> "$AllTimeFile" 2>/dev/null
                    trim_all_time_log
                fi
            fi
            OptimizedPidsMap[$pid]=$(date +%s)
        else
            if [ -z "${OptimizedPidsMap[$pid]}" ]; then
                local status_msg="OPTIMIZED"
                [ "$DryRun" = true ] && status_msg="DRY RUN ($status_msg)"
                status_log "$pid" "$proc_comm" "$simplified_cmd" "$raw_current_affinity" "$status_msg" "$overrides"
                OptimizedPidsMap[$pid]=$(date +%s)
                LastOptimizationTime=$(date +%s)
                SummarySilenced=false
            fi
        fi

        # Restore globals for next process in the loop
    done
}

# Periodically prints a summary of optimized processes
summarize_optimizations() {
    local force_summary=${1:-false}
    local now=$(date +%s)

    # First, cleanup dead processes to get an accurate count
    for pid in "${!OptimizedPidsMap[@]}"; do
        if [ ! -d "$PROC_PREFIX/proc/$pid" ]; then
            unset "OptimizedPidsMap[$pid]"
        fi
    done

    local current_optimized_count=${#OptimizedPidsMap[@]}

    # Trigger summary if forced, interval passed, or if we just dropped to zero optimized processes
    local should_summarize=false
    if [ "$force_summary" = true ] || [ $((now - LastSummaryTime)) -ge "$SummaryInterval" ]; then
        should_summarize=true
    elif [ "$LastOptimizedCount" -gt 0 ] && [ "$current_optimized_count" -eq 0 ]; then
        should_summarize=true
    fi

    LastOptimizedCount=$current_optimized_count

    local summary_msg=""
    if [ "$current_optimized_count" -eq 0 ]; then
        trigger_system_management "restore"
        summary_msg="No processes currently optimized"
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

        PcieWarningLogged=false
        if [ "$current_optimized_count" -gt 0 ]; then
            check_pcie_speed
        fi

        # Sort PIDs numerically for consistent output
        local sorted_pids=$(echo "${!OptimizedPidsMap[@]}" | tr ' ' '\n' | sort -n)

        for pid in $sorted_pids; do
            local raw_current_affinity=$(taskset -pc "$pid" 2>/dev/null | awk -F': ' '{print $2}')
            local proc_comm=$(ps -p "$pid" -o comm= 2>/dev/null)
            local full_proc_cmd=$(ps -fp "$pid" -o args= 2>/dev/null | tail -n 1)
            [ -z "$full_proc_cmd" ] && full_proc_cmd="[Hidden or Exited]"

            # Re-extract simplified_cmd for summary
            local simplified_cmd=$(get_simplified_cmd "$pid" "$proc_comm" "$full_proc_cmd")

            # Load per-process configuration to find overrides for summary
            local overrides=$(
                load_process_config "$simplified_cmd"
                get_overrides "$GlobalUseHt" "$GlobalIncludeNearby" "$GlobalMaxDist" "$GlobalStrictMem"
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
        AllTimeFile="${target_home}/.gpu_numa_optimizations"
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
            -f|--max-perf) MaxPerf=true; shift ;;
            -n|--dry-run) DryRun=true; shift ;;
            -c|--no-config) AutoGenConfig=false; shift ;;
            -k|--no-drop) DropPrivs=false; shift ;;
            --comm-pipe) CommPipe=$2; shift 2 ;;
            -m|--max-log-lines) 
                if [[ "$2" =~ ^[0-9]+$ ]]; then
                    MaxAllTimeLogLines=$2; shift 2
                else
                    echo "Error: --max-log-lines requires a numeric argument." >&2
                    exit 1
                fi
                ;;
            -h|--help) usage ;;
            -*) echo "Unknown option: $1" ; usage ;;
            *) 
                if [[ "$1" =~ ^[0-9]+$ ]]; then
                    GpuIndexArg=$1; shift
                else
                    echo "Error: GPU index must be a numeric value: $1" >&2
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
                echo "Warning: '$cmd' not found. Desktop notifications or privilege dropping may be limited."
            else
                echo "Error: Required command '$cmd' not found."
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
    system_manage_settings "tune"
    detect_target_user

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

    detect_gpu
    discover_resources
    filter_cpus
    load_all_time_stats

    # Capture global configuration baseline for override detection
    GlobalUseHt="$UseHt"
    GlobalIncludeNearby="$IncludeNearby"
    GlobalMaxDist="$MaxDist"
    GlobalStrictMem="$StrictMem"

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
            run_optimization

            # Aggregate notifications to avoid spamming the user.
            # If optimizations were performed, wait a short while for related processes
            # (e.g., a game launcher starting the game engine) to appear.
            if [ ${#PendingOptimizations[@]} -gt 0 ]; then
                log "Optimized ${#PendingOptimizations[@]} process(es). Waiting ${SleepInterval}s to aggregate more..."
                # Run one more time to catch immediate followers
                run_optimization
                flush_notifications
            fi

            summarize_optimizations
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
