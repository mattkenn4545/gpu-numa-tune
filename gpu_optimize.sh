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
DryRun=false                 # If true, log intended changes but do not apply them
DropPrivs=true               # If true, drop from root to the logged-in user after system tuning
MaxAllTimeLogLines=10000     # Maximum number of lines to keep in the all-time optimization log

# State Tracking
declare -A OptimizedPidsMap  # Map of PID -> Unix timestamp of when it was first optimized
TotalOptimizedCount=0        # Total number of unique processes optimized since script start
LastOptimizedCount=0         # Number of optimized processes in the last check
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

# Displays a formatted table row for process optimization status
status_log() {
    local pid="$1"
    local exe="$2"
    local affinity="$3"
    local status="$4"
    local cmd="$5"

    if [ "$LogLineCount" -ge "$HeaderInterval" ]; then
        LogLineCount=0

        echo "------------------------------------------------------------------------------------------------"
        status_log "PID" "EXE" "ORIG AFFINITY" "STATUS" "COMMAND"
        echo "------------------------------------------------------------------------------------------------"
    fi

    [ -z "$pid" ] && return

    printf "%-10s | %-15s | %-18s | %-25s | %s\n" "$pid" "$exe" "$affinity" "$status" "$cmd"
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
    echo "  -n, --dry-run        Dry-run mode (don't apply any changes)"
    echo "  -k, --no-drop        Keep root privileges (do not drop to user)"
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

# Identifies the GPU's PCI address based on the provided index.
detect_gpu() {
    # Preferred: GPUs with active render nodes
    mapfile -t active_gpus < <(
        for d in "$DEV_PREFIX"/dev/dri/renderD*; do
            [ -e "$d" ] || continue
            # Get PCI address from sysfs for this render node
            # /dev/dri/renderD128 -> /sys/class/drm/renderD128/device
            pci_path=$(readlink -f "$SYSFS_PREFIX/sys/class/drm/$(basename "$d")/device" 2>/dev/null)
            if [[ "$pci_path" =~ ([0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-9a-fA-F])$ ]]; then
                echo "${BASH_REMATCH[1]}"
            fi
        done | sort -u
    )

    # Fallback/Additional: Known GPU vendors if no render nodes or to complement
    mapfile -t vendor_gpus < <(lspci -D | grep -iE "NVIDIA|Advanced Micro Devices|Intel Corporation" | grep -iE "VGA|3D" | awk '{print $1}')
    
    # Merge and deduplicate
    mapfile -t all_gpu_pci < <(printf "%s\n" "${active_gpus[@]}" "${vendor_gpus[@]}" | grep -v "^$" | sort -u)

    GpuIndexArg=${GpuIndexArg:-0}

    if [ "${#all_gpu_pci[@]}" -eq 0 ]; then
        # Last resort: any VGA/3D device
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
discover_resources() {
    local device_sys_dir="$SYSFS_PREFIX/sys/bus/pci/devices/$PciAddr"
    if [ ! -d "$device_sys_dir" ]; then
        echo "Error: PCI device directory $device_sys_dir not found."
        exit 1
    fi

    NumaNodeId=$(cat "$device_sys_dir/numa_node" 2>/dev/null || echo -1)
    RawCpuList=$(cat "$device_sys_dir/local_cpulist" 2>/dev/null || echo "")

    NearbyNodeIds="$NumaNodeId"
    if [ "$IncludeNearby" = true ]; then
        NearbyNodeIds=$(get_nearby_nodes "$NumaNodeId")
    fi

    if [ -n "$NearbyNodeIds" ] && [ "$NearbyNodeIds" != "$NumaNodeId" ] && [ "$NearbyNodeIds" != "-1" ]; then
        RawCpuList=$(get_nodes_cpulist "$NearbyNodeIds")
    fi

    if [ -z "$RawCpuList" ]; then
        echo "Warning: Could not determine local CPU list for GPU. Falling back to all CPUs."
        RawCpuList=$(cat "$SYSFS_PREFIX/sys/devices/system/cpu/online" 2>/dev/null)
    fi
}

# Returns a comma-separated list of NUMA nodes within MaxDist of the target node.
# This uses 'numactl --hardware' to determine the relative distance between nodes.
get_nearby_nodes() {
    local target_node=$1
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
                if [ "$dist" -le "$MaxDist" ]; then
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
filter_cpus() {
    FinalCpuMask=""
    if [ "$UseHt" = true ]; then
        FinalCpuMask="$RawCpuList"
    else
        IFS=',' read -ra cpu_ranges <<< "$RawCpuList"
        for range in "${cpu_ranges[@]}"; do
            [ -z "$range" ] && continue
            # shellcheck disable=SC2086
            [[ $range == *-* ]] && expanded_list=$(seq ${range%-*} ${range#*-}) || expanded_list=$range
            for cpu_id in $expanded_list; do
                sibling_file="$SYSFS_PREFIX/sys/devices/system/cpu/cpu$cpu_id/topology/thread_siblings_list"
                if [ -f "$sibling_file" ]; then
                    # shellcheck disable=SC2002
                    first_sibling=$(cat "$sibling_file" | cut -d',' -f1 | cut -d'-' -f1)
                    [[ "$cpu_id" -eq "$first_sibling" ]] && FinalCpuMask+="$cpu_id,"
                fi
            done
        done
        FinalCpuMask=${FinalCpuMask%,}
    fi

    TargetNormalizedMask=$(normalize_affinity "$FinalCpuMask")
}

# --- Process Analysis & Filtering ---

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
        steamwebhelper|Discord|slack|teams|obs|obs64|heroic|lutris) return 1 ;;
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
    if echo "$proc_args" | grep -qiE "\.exe|wine|proton|reaper|Game\.x86_64|UnityPlayer|UnrealEditor"; then
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

# Applies system-wide low-latency and NUMA-related optimizations (requires root)
system_tune() {
    [ "$SkipSystemTune" = true ] && return

    if [ "$EUID" -eq 0 ]; then
        echo "--> Root detected. Applying system-wide optimizations..."

        set_sysctl() {
            local key="$1"
            local value="$2"
            local label="$3"
            # Check if the sysctl key exists before attempting to set it
            if [ -f "/proc/sys/${key//./ /}" ] || sysctl "$key" >/dev/null 2>&1; then
                if [ "$DryRun" = false ]; then
                    sysctl -w "$key=$value" >/dev/null
                    printf "  [OK] %-30s -> %-10s (%s)\n" "$key" "$value" "$label"
                else
                    printf "  [DRY] %-29s -> %-10s (%s)\n" "$key" "$value" "$label"
                fi
            else
                printf "  [SKIP] %-28s (Not supported by kernel)\n" "$key"
            fi
        }

        # vm.max_map_count: Increased for games with many memory mappings (e.g., Star Citizen, many Proton games)
        set_sysctl "vm.max_map_count" "2147483647" "Memory Mapping"
        # kernel.numa_balancing: Disabled to prevent the kernel from automatically moving pages between NUMA nodes,
        # which can cause inconsistent performance. We handle placement manually.
        set_sysctl "kernel.numa_balancing" "0" "NUMA Contention"
        # kernel.split_lock_mitigate: Disabled to avoid performance penalties when a process performs split-locks.
        set_sysctl "kernel.split_lock_mitigate" "0" "Execution Latency"
        # kernel.sched_migration_cost_ns: Increased to make the scheduler less aggressive about moving tasks
        # between CPUs, which helps maintain cache locality.
        set_sysctl "kernel.sched_migration_cost_ns" "5000000" "Scheduler"
        # net.core.netdev_max_backlog: Increased for better handling of high-speed network traffic.
        set_sysctl "net.core.netdev_max_backlog" "5000" "Network"
        # Busy polling/reading: Lowers network latency for online games.
        set_sysctl "net.core.busy_read" "50" "Network Latency"
        set_sysctl "net.core.busy_poll" "50" "Network Latency"
        # vm.stat_interval: Increased to reduce background "jitter" from virtual memory statistics gathering.
        set_sysctl "vm.stat_interval" "10" "Jitter Reduction"
        # kernel.nmi_watchdog: Disabled to reduce periodic interrupts that can cause micro-stutters.
        set_sysctl "kernel.nmi_watchdog" "0" "Interrupt Latency"

        # Transparency Hugepages (THP): 'never' or 'madvise' reduces micro-stutters in games
        if [ -f /sys/kernel/mm/transparent_hugepage/enabled ]; then
            if [ "$DryRun" = false ]; then
                echo "never" > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null
                printf "  [OK] %-30s -> %-10s (%s)\n" "transparent_hugepage" "never" "Latency"
            else
                printf "  [DRY] %-29s -> %-10s (%s)\n" "transparent_hugepage" "never" "Latency"
            fi
        fi
        if [ -f /sys/kernel/mm/transparent_hugepage/defrag ]; then
            if [ "$DryRun" = false ]; then
                echo "never" > /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null
                printf "  [OK] %-30s -> %-10s (%s)\n" "thp_defrag" "never" "Latency"
            else
                printf "  [DRY] %-29s -> %-10s (%s)\n" "thp_defrag" "never" "Latency"
            fi
        fi

        # CPU Scaling Governor: Set to 'performance' for all cores
        if [ -d /sys/devices/system/cpu/cpufreq ]; then
            if [ "$DryRun" = false ]; then
                for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
                    [ -f "$gov" ] && echo "performance" > "$gov" 2>/dev/null
                done
                printf "  [OK] %-30s -> %-10s (%s)\n" "cpu_governor" "performance" "Power/Perf"
            else
                printf "  [DRY] %-29s -> %-10s (%s)\n" "cpu_governor" "performance" "Power/Perf"
            fi
        fi

        if pgrep -x numad >/dev/null 2>&1; then
            echo "  [WARNING] numad daemon is running. This may contend with manual optimization."
            echo "            Consider stopping it: 'sudo systemctl stop numad'"
        fi

        echo "--> System tuning complete."
        echo "------------------------------------------------------------------------------------------------"
    else
        echo "------------------------------------------------------------------------------------------------"
        echo "WARNING: Not running as root. Latency tuning skipped."
        echo "------------------------------------------------------------------------------------------------"
        sleep 1
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

        local raw_current_affinity=$(taskset -pc "$pid" 2>/dev/null | awk -F': ' '{print $2}')
        [ -z "$raw_current_affinity" ] && continue
        local current_normalized_mask=$(normalize_affinity "$raw_current_affinity")
        local proc_comm=$(ps -p "$pid" -o comm=)
        local full_proc_cmd=$(ps -fp "$pid" -o args= | tail -n 1)
        [ -z "$full_proc_cmd" ] && full_proc_cmd="[Hidden or Exited]"

        if [ "$current_normalized_mask" != "$TargetNormalizedMask" ]; then
            if [ "$DryRun" = false ]; then
                taskset -pc "$FinalCpuMask" "$pid" > /dev/null 2>&1

                if [ "$StrictMem" = true ]; then
                    numactl --membind="${NearbyNodeIds:-$NumaNodeId}" -p "$pid" > /dev/null 2>&1
                else
                    # Preferred policy: try multiple nodes if available, fallback to single
                    if [[ "$NearbyNodeIds" == *","* ]]; then
                        if ! numactl --preferred-many="$NearbyNodeIds" -p "$pid" > /dev/null 2>&1; then
                             numactl --preferred="${NearbyNodeIds%%,*}" -p "$pid" > /dev/null 2>&1
                        fi
                    else
                        numactl --preferred="${NearbyNodeIds:-$NumaNodeId}" -p "$pid" > /dev/null 2>&1
                    fi
                fi
            fi

            local process_rss_kb=$(awk '/VmRSS/ {print $2}' "$PROC_PREFIX/proc/$pid/status" 2>/dev/null || echo 0)
            local safety_margin_kb=524288

            # Extract a simplified executable name for notifications
            local simplified_cmd=""
            if [[ "$full_proc_cmd" =~ \.[eE][xX][eE] ]]; then
                simplified_cmd=$(echo "$full_proc_cmd" | sed 's/\.[eE][xX][eE].*/.exe/i' | sed 's/.*[\\\/]//')
            elif [ "$full_proc_cmd" != "[Hidden or Exited]" ]; then
                simplified_cmd=$(echo "$full_proc_cmd" | awk '{print $1}' | sed 's/.*[\\\/]//')
            fi
            # Ensure simplified_cmd is not empty
            [ -z "$simplified_cmd" ] && simplified_cmd="$proc_comm"
            [ -z "$simplified_cmd" ] && simplified_cmd="Process $pid"

            local free_kb=0
    if [ -n "$NearbyNodeIds" ] && [ "$NearbyNodeIds" != "-1" ]; then
        IFS=',' read -ra nodes <<< "$NearbyNodeIds"
        for node in "${nodes[@]}"; do
            free_kb=$((free_kb + $(get_node_free_kb "$node")))
        done
    elif [ "$NumaNodeId" -ge 0 ]; then
        free_kb=$(get_node_free_kb "$NumaNodeId")
    else
        # No specific NUMA node, but let's assume we can move if we want? 
        # Actually migratepages needs target nodes. If we have no nodes, we can't move.
        free_kb=0
    fi

            # Migrate pages if there's enough free memory
            local target_nodes="${NearbyNodeIds:-$NumaNodeId}"
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
                status_msg="OPTIMIZED"
            else
                status_msg="OPTIMIZED (NODE FULL)"
            fi

            if [ "$DryRun" = true ]; then
                status_msg="DRY RUN ($status_msg)"
            fi

            # Queue for notification
            PendingOptimizations+=("$pid|$proc_comm|$simplified_cmd|$status_msg|$target_nodes|$process_rss_kb")
            status_log "$pid" "$proc_comm" "$raw_current_affinity" "$status_msg" "$full_proc_cmd"

            if [ -z "${OptimizedPidsMap[$pid]}" ]; then
                ((TotalOptimizedCount++))
                ((LifetimeOptimizedCount++))
                LastOptimizationTime=$(date +%s)
                SummarySilenced=false
                if [ "$DryRun" = false ] && [ -n "$AllTimeFile" ]; then
                    # Log entry format: TIMESTAMP | PID | COMM | STATUS | NODES | COMMAND
                    printf "%-19s | %-8s | %-16s | %-22s | %-8s | %s\n" \
                        "$(date "+%Y-%m-%d %H:%M:%S")" "$pid" "$proc_comm" "$status_msg" "$target_nodes" "$full_proc_cmd" >> "$AllTimeFile" 2>/dev/null
                    trim_all_time_log
                fi
            fi
            OptimizedPidsMap[$pid]=$(date +%s)
        else
            if [ -z "${OptimizedPidsMap[$pid]}" ]; then
                local status_msg="OPTIMIZED"
                [ "$DryRun" = true ] && status_msg="DRY RUN ($status_msg)"
                status_log "$pid" "$proc_comm" "$raw_current_affinity" "$status_msg" "$full_proc_cmd"
                OptimizedPidsMap[$pid]=$(date +%s)
                LastOptimizationTime=$(date +%s)
                SummarySilenced=false
            fi
        fi
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
    local summary_msg=""
    local summary_status="OPTIMIZED"

    # Trigger summary if forced, interval passed, or if we just dropped to zero optimized processes
    local should_summarize=false
    if [ "$force_summary" = true ] || [ $((now - LastSummaryTime)) -ge "$SummaryInterval" ]; then
        should_summarize=true
        if [ "$current_optimized_count" -eq 0 ]; then
            summary_msg="No processes currently optimized"
        fi
    elif [ "$LastOptimizedCount" -gt 0 ] && [ "$current_optimized_count" -eq 0 ]; then
        # Just dropped to zero, trigger immediate summary
        should_summarize=true
        summary_msg="No optimized processes remaining"
        summary_status="IDLE"
    fi

    LastOptimizedCount=$current_optimized_count

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

        echo "------------------------------------------------------------------------------------------------"
        status_log "$TotalOptimizedCount procs" "since startup" "$LifetimeOptimizedCount all time" "$summary_status" "$summary_msg"

        # Sort PIDs numerically for consistent output
        local sorted_pids=$(echo "${!OptimizedPidsMap[@]}" | tr ' ' '\n' | sort -n)

        for pid in $sorted_pids; do
            local raw_current_affinity=$(taskset -pc "$pid" 2>/dev/null | awk -F': ' '{print $2}')
            local proc_comm=$(ps -p "$pid" -o comm= 2>/dev/null)
            local full_proc_cmd=$(ps -fp "$pid" -o args= 2>/dev/null | tail -n 1)
            [ -z "$full_proc_cmd" ] && full_proc_cmd="[Hidden or Exited]"

            status_log "$pid" "$proc_comm" "$raw_current_affinity" "OPTIMIZED $(date -d "@${OptimizedPidsMap[$pid]}" "+%H:%M %D")" "$full_proc_cmd"
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
            -n|--dry-run) DryRun=true; shift ;;
            -k|--no-drop) DropPrivs=false; shift ;;
            -m|--max-log-lines) MaxAllTimeLogLines=$2; shift 2 ;;
            -h|--help) usage ;;
            -*) echo "Unknown option: $1" ; usage ;;
            *) GpuIndexArg=$1; shift ;;
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
        if [ -n "$NearbyNodeIds" ] && [ "$NearbyNodeIds" != "-1" ]; then
            echo "NUMA NODES       : $NearbyNodeIds (Nearby Max Distance $MaxDist)"
            IFS=',' read -ra nodes <<< "$NearbyNodeIds"
            for node in "${nodes[@]}"; do
               echo "NODE $node SIZE      : $(get_node_total_mb "$node") MB"
            done
        else
            echo "NUMA NODE        : $NumaNodeId"
            echo "NUMA NODE SIZE   : $(get_node_total_mb "$NumaNodeId") MB"
        fi
    fi

    echo "CPU TARGETS      : $( [ "$UseHt" = true ] && echo "HT Allowed" || echo "Physical Only" ) ($FinalCpuMask)"
    echo "MEM POLICY       : $mem_policy_label"
    echo "PROCESS FILTER   : $( [ "$OnlyGaming" = true ] && echo "Gaming Only" || echo "All GPU Processes" )"
    echo "DRY RUN MODE     : $( [ "$DryRun" = true ] && echo "ENABLED (No changes will be applied)" || echo "Disabled" )"
    echo "MODE             : $( [ "$DaemonMode" = true ] && echo "Daemon" || echo "Single-run" )"

    status_log
}

# --- Main Script Execution ---

# Entry point of the script. Handles initialization, privilege dropping, 
# and enters the main daemon loop or performs a single-run optimization.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "------------------------------------------------------------------------------------------------"
    parse_args "$@"
    check_dependencies
    system_tune
    detect_target_user

    # Drop privileges if a target user was detected, we are root, and dropping is enabled.
    # This allows the script to perform system tuning as root, then switch to the user
    # context for monitoring and optimizing user-owned processes.
    if [ "$DropPrivs" = true ] && [ "$EUID" -eq 0 ] && [ -n "$TargetUser" ]; then
        echo "--> Dropping privileges to $TargetUser..."
        # Re-execute the script as the target user. 
        # --no-tune: Skip system_tune in the child as it requires root.
        # --no-drop: Prevent infinite re-execution loops.
        exec setpriv --reuid="$TargetUid" --regid="$TargetGid" --init-groups -- "$0" "--no-tune" "--no-drop" "${OriginalArgs[@]}"
    fi

    detect_gpu
    discover_resources
    filter_cpus
    load_all_time_stats

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
                log "Optimized ${#PendingOptimizations[@]} process(es). Waiting ${SleepInterval} to aggregate more..."
                sleep "$SleepInterval"
                # Run one more time to catch immediate followers
                run_optimization
                flush_notifications
            fi

            summarize_optimizations
            sleep "$SleepInterval"
        done
    else
        # Single-run mode
        run_optimization
        flush_notifications
        echo "------------------------------------------------------------------------------------------------"
        echo "Optimization complete."
    fi
fi
