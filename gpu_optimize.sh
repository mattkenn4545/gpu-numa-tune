#!/bin/bash

# ==============================================================================
# GPU NUMA Optimizer - Cross-Vendor Version (NVIDIA/AMD/Intel)
# Optimizes gaming performance via CPU pinning, memory migration, and sysctl.
# ==============================================================================

# --- Global Configuration ---
UseHt=true
DaemonMode=false
SleepInterval=10
StrictMem=false
IncludeNearby=true
MaxDist=11
OnlyGaming=true
SkipSystemTune=false
DropPrivs=true

# Tracking for optimized processes
declare -A OptimizedPidsMap
TotalOptimizedCount=0
LastSummaryTime=$(date +%s)
SummaryInterval=600 # 10 minutes
LogLineCount=9999
HeaderInterval=20

# Buffer for pending notifications to avoid spam
declare -a PendingOptimizations

# Save original arguments for re-execution after privilege dropping
OriginalArgs=("$@")

# Detected User (for privilege dropping)
TargetUser=""
TargetUid=""
TargetGid=""

# Functions

# --- Utilities & Logging ---

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

    printf "%-8s | %-15s | %-18s | %-25s | %s\n" "$pid" "$exe" "$affinity" "$status" "$cmd"
    ((LogLineCount++))
}

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
    echo "  -k, --no-drop        Keep root privileges (do not drop to user)"
    echo "  -h, --help           Show this help message"
    echo
    echo "Arguments:"
    echo "  gpu_index            Index of the GPU from lspci (default: 0)"
    exit 0
}

notify_user() {
    local title="$1"
    local message="$2"
    local icon="${3:-dialog-information}"

    if command -v notify-send >/dev/null 2>&1; then
        # We assume we are now running as the target user (or root if none detected)
        # We still ensure DBUS and XDG vars are set for notify-send to work in a daemon context
        if [ -n "$TargetUid" ]; then
            env DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$TargetUid/bus" \
                XDG_RUNTIME_DIR="/run/user/$TargetUid" \
                notify-send -a "GPU NUMA Optimizer" -i "$icon" "$title" "$message" >/dev/null 2>&1
        else
            notify-send -a "GPU NUMA Optimizer" -i "$icon" "$title" "$message" >/dev/null 2>&1
        fi
    fi
}

flush_notifications() {
    [ ${#PendingOptimizations[@]} -eq 0 ] && return

    # Sort pending optimizations by RSS size (last field) descending
    # We use a temporary array to store sorted results
    local sorted_pending=()
    if [ ${#PendingOptimizations[@]} -gt 1 ]; then
        # Use printf to handle potential spaces and pipe to sort
        # Fields: pid|comm|simplified|status|nodes|rss
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

detect_gpu() {
    mapfile -t all_vga_devices < <(lspci -D | grep -iE 'vga|3d')
    GpuIndexArg=${GpuIndexArg:-0}

    if [ "${#all_vga_devices[@]}" -eq 0 ]; then
        echo "Error: No GPU (VGA/3D) devices detected via lspci."
        exit 1
    fi

    if [ "$GpuIndexArg" -ge "${#all_vga_devices[@]}" ]; then
        echo "Error: GPU index $GpuIndexArg not found (Found ${#all_vga_devices[@]} GPUs)."
        exit 1
    fi

    PciAddr=$(echo "${all_vga_devices[$GpuIndexArg]}" | awk '{print $1}')

    if [ -z "$PciAddr" ]; then
        echo "Error: Could not determine PCI address for GPU index $GpuIndexArg."
        exit 1
    fi
}

discover_resources() {
    local device_sys_dir="/sys/bus/pci/devices/$PciAddr"
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

    if [ -n "$NearbyNodeIds" ] && [ "$NearbyNodeIds" != "$NumaNodeId" ]; then
        RawCpuList=$(get_nodes_cpulist "$NearbyNodeIds")
    fi

    if [ -z "$RawCpuList" ]; then
        echo "Warning: Could not determine local CPU list for GPU. Falling back to all CPUs."
        RawCpuList=$(cat /sys/devices/system/cpu/online 2>/dev/null)
    fi
}

get_nearby_nodes() {
    local target_node=$1
    local nearby=()

    if [ "$target_node" -lt 0 ]; then
        echo ""
        return
    fi

    # Use numactl to get distances if available
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

    # Fallback to just the target node
    echo "$target_node"
}

get_nodes_cpulist() {
    local nodes=$1
    local combined=""
    IFS=',' read -ra node_list <<< "$nodes"
    for node in "${node_list[@]}"; do
        local cpulist=$(cat "/sys/devices/system/node/node$node/cpulist" 2>/dev/null)
        [ -n "$cpulist" ] && combined+="$cpulist,"
    done
    echo "${combined%,}"
}

get_node_free_kb() {
    # shellcheck disable=SC2086
    local free_kb=$(grep -i "Node $1 MemFree" /sys/devices/system/node/node$1/meminfo 2>/dev/null | awk '{print $4}')
    echo "${free_kb:-0}"
}

get_node_total_mb() {
    # shellcheck disable=SC2086
    local total_kb=$(grep -i "Node $1 MemTotal" /sys/devices/system/node/node$1/meminfo 2>/dev/null | awk '{print $4}')
    echo "$(( ${total_kb:-0} / 1024 ))"
}

get_node_used_mb() {
    # shellcheck disable=SC2086
    local used_kb=$(grep -i "Node $1 MemUsed" /sys/devices/system/node/node$1/meminfo 2>/dev/null | awk '{print $4}')
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

normalize_affinity() {
    # shellcheck disable=SC2162
    echo "$1" | tr ',' '\n' | while read r; do
        # shellcheck disable=SC2086
        if [[ $r == *-* ]]; then seq ${r%-*} ${r#*-}; else echo $r; fi
    done | sort -n | tr '\n' ',' | sed 's/,$//'
}

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
                sibling_file="/sys/devices/system/cpu/cpu$cpu_id/topology/thread_siblings_list"
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

is_gaming_process() {
    local pid="$1"

    # If OnlyGaming is false, we can optimize anything that uses the GPU
    [ "$OnlyGaming" = false ] && return 0

    # 1. Known Blacklist (Non-gaming GPU heavy apps)
    local proc_comm=$(ps -p "$pid" -o comm= 2>/dev/null)
    case "$proc_comm" in
        Xorg|gnome-shell|kwin_wayland|sway|wayland|Xwayland) return 1 ;;
        chrome|firefox|brave|msedge|opera|browser) return 1 ;;
        steamwebhelper|Discord|slack|teams|obs|obs64|heroic) return 1 ;;
    esac

    # 2. Heuristics (Exclude Electron/Chrome-based UI processes like Heroic or Steam's web helper)
    local proc_args=$(ps -fp "$pid" -o args= 2>/dev/null)
    if echo "$proc_args" | grep -qE -- "--type=(zygote|renderer|gpu-process|utility)"; then
        return 1
    fi

    # 3. Gaming Environment Variables
    if [ -r "/proc/$pid/environ" ]; then
        # Check for Steam, Proton, Lutris, Heroic markers
        if tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | grep -qE "^(STEAM_COMPAT_APP_ID|STEAM_GAME_ID|LUTRIS_GAME_ID|HEROIC_APP_NAME|PROTON_VER|WINEPREFIX)="; then
            return 0
        fi
    fi

    # 4. Heuristics (Wine/Proton processes, Game executables)
    if echo "$proc_args" | grep -qiE "\.exe|wine|proton|reaper|Game\.x86_64|UnityPlayer"; then
        return 0
    fi

    # 5. Check Parent Processes (up to 3 levels)
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

system_tune() {
    [ "$SkipSystemTune" = true ] && return

    if [ "$EUID" -eq 0 ]; then
        echo "--> Root detected. Applying system-wide optimizations..."

        set_sysctl() {
            local key="$1"
            local value="$2"
            local label="$3"
            if [ -f "/proc/sys/${key//./ /}" ] || sysctl "$key" >/dev/null 2>&1; then
                sysctl -w "$key=$value" >/dev/null
                printf "  [OK] %-30s -> %-10s (%s)\n" "$key" "$value" "$label"
            else
                printf "  [SKIP] %-28s (Not supported by kernel)\n" "$key"
            fi
        }

        set_sysctl "vm.max_map_count" "2147483647" "Memory Mapping"
        set_sysctl "kernel.numa_balancing" "0" "NUMA Contention"
        set_sysctl "kernel.split_lock_mitigate" "0" "Execution Latency"
        set_sysctl "kernel.sched_migration_cost_ns" "5000000" "Scheduler"
        set_sysctl "net.core.netdev_max_backlog" "5000" "Network"
        set_sysctl "net.core.busy_read" "50" "Network Latency"
        set_sysctl "net.core.busy_poll" "50" "Network Latency"
        set_sysctl "vm.stat_interval" "10" "Jitter Reduction"
        set_sysctl "kernel.nmi_watchdog" "0" "Interrupt Latency"

        # --- Transparency Hugepages (THP) ---
        # THP can cause micro-stutters during allocation. 'madvise' or 'never' is often better for gaming.
        if [ -f /sys/kernel/mm/transparent_hugepage/enabled ]; then
            echo "never" > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null
            printf "  [OK] %-30s -> %-10s (%s)\n" "transparent_hugepage" "never" "Latency"
        fi
        if [ -f /sys/kernel/mm/transparent_hugepage/defrag ]; then
            echo "never" > /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null
            printf "  [OK] %-30s -> %-10s (%s)\n" "thp_defrag" "never" "Latency"
        fi

        # --- CPU Scaling Governor ---
        # Set performance governor for all CPUs. While we ideally only target CPUs on the GPU's NUMA node,
        # we do this at the system level here because it's a one-time pre-priv-drop optimization.
        if [ -d /sys/devices/system/cpu/cpufreq ]; then
            for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
                [ -f "$gov" ] && echo "performance" > "$gov" 2>/dev/null
            done
            printf "  [OK] %-30s -> %-10s (%s)\n" "cpu_governor" "performance" "Power/Perf"
        fi

        if pgrep -x numad >/dev/null 2>&1; then
            echo "  [WARNING] numad daemon is running. This may contend with manual optimization."
            echo "            Consider stopping it: 'sudo systemctl stop numad'"
            echo "            Or uninstalling it: 'sudo apt remove numad' or 'sudo dnf remove numad'"
        fi

        echo "--> System tuning complete."
        echo "--------------------------------------------------------"
    else
        echo "--------------------------------------------------------"
        echo "WARNING: Not running as root. Latency tuning skipped."
        echo "--------------------------------------------------------"
        sleep 1
    fi
}

# --- Core Logic & Execution ---

run_optimization() {
    # Cross-vendor PID detection (Render nodes and NVIDIA devices)
    local gpu_pids=$(fuser /dev/dri/renderD* /dev/nvidia* 2>/dev/null | tr ' ' '\n' | sort -u)

    for pid in $gpu_pids; do
        [[ -z "$pid" ]] && continue
        if [ "$pid" -lt 100 ] || [ ! -d "/proc/$pid" ]; then continue; fi
        # If we are not root, we can only optimize processes we own
        if [ "$EUID" -ne 0 ] && [ ! -O "/proc/$pid" ]; then
            # We skip with a log if it's potentially a game but we don't own it
            # but only if OnlyGaming is true, otherwise it's expected
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
            taskset -pc "$FinalCpuMask" "$pid" > /dev/null 2>&1

            if [ "$StrictMem" = true ]; then
                numactl --membind="${NearbyNodeIds:-$NumaNodeId}" -p "$pid" > /dev/null 2>&1
            else
                # Try preferred-many if multiple nodes are present, fallback to preferred
                if [[ "$NearbyNodeIds" == *","* ]]; then
                    if ! numactl --preferred-many="$NearbyNodeIds" -p "$pid" > /dev/null 2>&1; then
                         numactl --preferred="${NearbyNodeIds%%,*}" -p "$pid" > /dev/null 2>&1
                    fi
                else
                    numactl --preferred="${NearbyNodeIds:-$NumaNodeId}" -p "$pid" > /dev/null 2>&1
                fi
            fi

            local process_rss_kb=$(awk '/VmRSS/ {print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)
            local safety_margin_kb=524288

            # Extract the executable name (head of the command) for cleaner notifications
            # We handle Windows paths and potential spaces in the executable path (common in Steam/Proton)
            local simplified_cmd=""
            if [[ "$full_proc_cmd" =~ \.[eE][xX][eE] ]]; then
                # For Windows executables, take everything up to .exe
                simplified_cmd=$(echo "$full_proc_cmd" | sed 's/\.[eE][xX][eE].*/.exe/i' | sed 's/.*[\\\/]//')
            else
                # For Linux, take the first word and get its basename
                simplified_cmd=$(echo "$full_proc_cmd" | awk '{print $1}' | sed 's/.*[\\\/]//')
            fi

            local free_kb=0
            if [ -n "$NearbyNodeIds" ]; then
                IFS=',' read -ra nodes <<< "$NearbyNodeIds"
                for node in "${nodes[@]}"; do
                    free_kb=$((free_kb + $(get_node_free_kb "$node")))
                done
            else
                free_kb=$(get_node_free_kb "$NumaNodeId")
            fi

            if [ "$free_kb" -gt $((process_rss_kb + safety_margin_kb)) ]; then
                if migratepages "$pid" all "${NearbyNodeIds:-$NumaNodeId}" > /dev/null 2>&1; then
                    status_msg="OPTIMIZED & MOVED"
                else
                    status_msg="OPTIMIZED (MOVE FAILED)"
                fi
            else
                status_msg="OPTIMIZED (NODE FULL)"
            fi

            # Queue for notification
            PendingOptimizations+=("$pid|$proc_comm|$simplified_cmd|$status_msg|${NearbyNodeIds:-$NumaNodeId}|$process_rss_kb")

            status_log "$pid" "$proc_comm" "$raw_current_affinity" "$status_msg" "$full_proc_cmd"
        else
            # Already optimized
            if [ -z "${OptimizedPidsMap[$pid]}" ]; then
                # If we are in startup phase or just noticed it, print it
                status_log "$pid" "$proc_comm" "$raw_current_affinity" "OPTIMIZED" "$full_proc_cmd"
            fi
        fi

        if [ -z "${OptimizedPidsMap[$pid]}" ]; then
            OptimizedPidsMap[$pid]=$(date +%s)
            ((TotalOptimizedCount++))
        fi
    done
}

check_active_optimizations() {
    local now=$(date +%s)
    if [ $((now - LastSummaryTime)) -ge "$SummaryInterval" ]; then
        if [ ${#OptimizedPidsMap[@]} -eq 0 ]; then
            echo "No processes currently optimized"
        else
            echo "PERIODIC STATUS SUMMARY ($(date "+%Y-%m-%d %H:%M:%S")) - $TotalOptimizedCount processes optimized since startup"

            # Sort PIDs numerically for consistent output
            local sorted_pids=$(echo "${!OptimizedPidsMap[@]}" | tr ' ' '\n' | sort -n)

            for pid in $sorted_pids; do
                if [ -d "/proc/$pid" ]; then
                    local raw_current_affinity=$(taskset -pc "$pid" 2>/dev/null | awk -F': ' '{print $2}')
                    local proc_comm=$(ps -p "$pid" -o comm= 2>/dev/null)
                    local full_proc_cmd=$(ps -fp "$pid" -o args= 2>/dev/null | tail -n 1)
                    [ -z "$full_proc_cmd" ] && full_proc_cmd="[Hidden or Exited]"

                    status_log "$pid" "$proc_comm" "$raw_current_affinity" "OPTIMIZED $(date -d "@${OptimizedPidsMap[$pid]}" "+%H:%M %D")" "$full_proc_cmd"
                else
                    unset "OptimizedPidsMap[$pid]"
                fi
            done
            echo "------------------------------------------------------------------------------------------------"
        fi
        LastSummaryTime=$now
    fi
}

# --- CLI & Startup ---

parse_args() {
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            -p|--physical-only) UseHt=false; shift ;;
            -d|--daemon) DaemonMode=true; shift ;;
            -s|--strict) StrictMem=true; shift ;;
            -l|--local-only) IncludeNearby=false; shift ;;
            -a|--all-gpu-procs) OnlyGaming=false; shift ;;
            -x|--no-tune) SkipSystemTune=true; shift ;;
            -k|--no-drop) DropPrivs=false; shift ;;
            -h|--help) usage ;;
            -*) echo "Unknown option: $1" ; usage ;;
            *) GpuIndexArg=$1; shift ;;
        esac
    done
}

check_dependencies() {
    local deps=("lspci" "fuser" "taskset" "numactl" "migratepages" "awk" "ps" "notify-send" "setpriv")
    # Added /usr/sbin to path for setpriv and other system tools
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

print_banner() {
    local mem_policy_label=$([ "$StrictMem" = true ] && echo "Strict (OOM Risk)" || echo "Preferred (Safe)")
    
    echo "------------------------------------------------------------------------------------------------"
    echo "GPU MODEL        :$(lspci -s "$PciAddr" | cut -d: -f3) ($PciAddr)"

    if [ "$NumaNodeId" -ge 0 ]; then
        if [ -n "$NearbyNodeIds" ]; then
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
    echo "MODE             : $( [ "$DaemonMode" = true ] && echo "Daemon" || echo "Single-run" )"

    status_log
}

# --- Main Script Execution ---

echo "--------------------------------------------------------"
parse_args "$@"
check_dependencies
system_tune
detect_target_user

# Drop privileges if a target user was detected, we are root, and dropping is enabled
if [ "$DropPrivs" = true ] && [ "$EUID" -eq 0 ] && [ -n "$TargetUser" ]; then
    echo "--> Dropping privileges to $TargetUser..."
    # Prepare the command to re-execute itself as the target user
    # We add --no-tune and --no-drop to avoid re-running system tuning and re-attempting priv drop
    exec setpriv --reuid="$TargetUid" --regid="$TargetGid" --init-groups -- "$0" "--no-tune" "--no-drop" "${OriginalArgs[@]}"
fi

detect_gpu
discover_resources
filter_cpus

print_banner
if [ "$DaemonMode" = true ]; then
    while true; do
        run_optimization

        # If we optimized something, wait SleepInterval + 5 before notifying
        # to catch any subsequent processes (e.g. game launcher -> game exe)
        if [ ${#PendingOptimizations[@]} -gt 0 ]; then
            log "Optimized ${#PendingOptimizations[@]} process(es). Waiting $((SleepInterval + 5))s to aggregate more..."
            sleep $((SleepInterval + 5))
            # Run one more time to catch immediate followers before flushing
            run_optimization
            flush_notifications
        fi

        check_active_optimizations
        sleep "$SleepInterval"
    done
else
    run_optimization
    flush_notifications
    echo "------------------------------------------------------------------------------------------------"
    echo "Optimization complete."
fi
