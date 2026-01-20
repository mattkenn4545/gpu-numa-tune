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
OnlyGaming=true

# Save original arguments for re-execution after privilege dropping
OriginalArgs=("$@")

# Detected User (for privilege dropping)
TargetUser=""
TargetUid=""
TargetGid=""

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

usage() {
    echo "Usage: $0 [options] [gpu_index]"
    echo
    echo "Options:"
    echo "  -p, --physical-only  Use only physical CPU cores (skip SMT/HT siblings)"
    echo "  -d, --daemon         Run in daemon mode (check every $SleepInterval seconds)"
    echo "  -s, --strict         Strict memory policy (OOM risk, but guaranteed local memory)"
    echo "  -a, --all-gpu-procs  Optimize ALL processes using the GPU (not just games)"
    echo "  -h, --help           Show this help message"
    echo
    echo "Arguments:"
    echo "  gpu_index            Index of the GPU from lspci (default: 0)"
    exit 0
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

log() {
    if [ "$DaemonMode" = true ]; then
        logger -t gpu-numa-tune "$1"
    else
        echo "$1"
    fi
}

# --- Root Check & Validated System Tuning ---
system_tune() {
    if [ "$EUID" -eq 0 ]; then
        echo "--------------------------------------------------------"
        echo "--> Root detected. Validating and applying optimizations..."

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

        # Check for numad daemon
        if ! command -v numad >/dev/null 2>&1; then
            echo "  [INFO] numad is not installed. Consider installing it for better NUMA resource management."
            echo "         (e.g., 'sudo apt install numad' or 'sudo dnf install numad')"
        elif ! pgrep -x numad >/dev/null 2>&1; then
            echo "  [INFO] numad is installed but not running. Consider starting it:"
            echo "         'sudo systemctl start numad'"
        else
            echo "  [OK] numad daemon is running."
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

# 1. Argument Parsing
while [[ "$1" =~ ^- ]]; do
    case $1 in
        -p|--physical-only) UseHt=false; shift ;;
        -d|--daemon) DaemonMode=true; shift ;;
        -s|--strict) StrictMem=true; shift ;;
        -a|--all-gpu-procs) OnlyGaming=false; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1" ; usage ;;
    esac
done

check_dependencies
system_tune
detect_target_user

# Drop privileges if a target user was detected and we are root
if [ "$EUID" -eq 0 ] && [ -n "$TargetUser" ]; then
    echo "--> Dropping privileges to $TargetUser..."
    # Prepare the command to re-execute itself as the target user
    exec setpriv --reuid="$TargetUid" --regid="$TargetGid" --init-groups -- "$0" "${OriginalArgs[@]}"
fi

# 2. Identify GPUs (NVIDIA, AMD, Intel)
mapfile -t all_vga_devices < <(lspci -D | grep -iE 'vga|3d')
gpu_index_arg=${1:-0}

if [ "${#all_vga_devices[@]}" -eq 0 ]; then
    echo "Error: No GPU (VGA/3D) devices detected via lspci."
    exit 1
fi

if [ "$gpu_index_arg" -ge "${#all_vga_devices[@]}" ]; then
    echo "Error: GPU index $gpu_index_arg not found (Found ${#all_vga_devices[@]} GPUs)."
    exit 1
fi

pci_addr=$(echo "${all_vga_devices[$gpu_index_arg]}" | awk '{print $1}')

if [ -z "$pci_addr" ]; then
    echo "Error: Could not determine PCI address for GPU index $gpu_index_arg."
    exit 1
fi

# 3. Identify NUMA Node and CPU List
device_sys_dir="/sys/bus/pci/devices/$pci_addr"
if [ ! -d "$device_sys_dir" ]; then
    echo "Error: PCI device directory $device_sys_dir not found."
    exit 1
fi

numa_node_id=$(cat "$device_sys_dir/numa_node" 2>/dev/null || echo -1)
raw_cpu_list=$(cat "$device_sys_dir/local_cpulist" 2>/dev/null || echo "")

if [ -z "$raw_cpu_list" ]; then
    echo "Warning: Could not determine local CPU list for GPU. Falling back to all CPUs."
    raw_cpu_list=$(cat /sys/devices/system/cpu/online 2>/dev/null)
fi

# 4. Filter CPU List (HT vs Physical)
final_cpu_mask=""
if [ "$UseHt" = true ]; then
    final_cpu_mask="$raw_cpu_list"
else
    IFS=',' read -ra cpu_ranges <<< "$raw_cpu_list"
    for range in "${cpu_ranges[@]}"; do
        [ -z "$range" ] && continue
        [[ $range == *-* ]] && expanded_list=$(seq ${range%-*} ${range#*-}) || expanded_list=$range
        for cpu_id in $expanded_list; do
            sibling_file="/sys/devices/system/cpu/cpu$cpu_id/topology/thread_siblings_list"
            if [ -f "$sibling_file" ]; then
                first_sibling=$(cat "$sibling_file" | cut -d',' -f1 | cut -d'-' -f1)
                [[ "$cpu_id" -eq "$first_sibling" ]] && final_cpu_mask+="$cpu_id,"
            fi
        done
    done
    final_cpu_mask=${final_cpu_mask%,}
fi

normalize_affinity() {
    echo "$1" | tr ',' '\n' | while read r; do
        if [[ $r == *-* ]]; then seq ${r%-*} ${r#*-}; else echo $r; fi
    done | sort -n | tr '\n' ',' | sed 's/,$//'
}

get_node_free_kb() {
    local free_kb=$(grep -i "Node $1 MemFree" /sys/devices/system/node/node$1/meminfo 2>/dev/null | awk '{print $4}')
    echo "${free_kb:-0}"
}

get_node_total_mb() {
    local total_kb=$(grep -i "Node $1 MemTotal" /sys/devices/system/node/node$1/meminfo 2>/dev/null | awk '{print $4}')
    echo "$(( ${total_kb:-0} / 1024 ))"
}

get_node_used_mb() {
    local used_kb=$(grep -i "Node $1 MemUsed" /sys/devices/system/node/node$1/meminfo 2>/dev/null | awk '{print $4}')
    echo "$(( ${used_kb:-0} / 1024 ))"
}

target_normalized_mask=$(normalize_affinity "$final_cpu_mask")
mem_policy_label=$([ "$StrictMem" = true ] && echo "Strict (OOM Risk)" || echo "Preferred (Safe)")

# --- Startup Output ---
echo "OPTIMIZING GPU   : $pci_addr"
echo "MODEL            :$(lspci -s "$pci_addr" | cut -d: -f3)"
echo "NUMA NODE        : $numa_node_id"

if [ "$numa_node_id" -ge 0 ]; then
    echo "NUMA NODE SIZE   : $(get_node_total_mb "$numa_node_id") MB"
    echo "NUMA NODE USED   : $(get_node_used_mb "$numa_node_id") MB"
fi

echo "CPU TARGETS      : $final_cpu_mask"
echo "MEM POLICY       : $mem_policy_label"
echo "PROCESS FILTER   : $( [ "$OnlyGaming" = true ] && echo "Gaming Only" || echo "All GPU Processes" )"
echo "MODE             : $( [ "$DaemonMode" = true ] && echo "Daemon" || echo "Single-run" )"
echo "--------------------------------------------------------"
printf "%-8s | %-15s | %-25s | %s\n" "PID" "EXE" "STATUS" "COMMAND"
echo "--------------------------------------------------------"

is_gaming_process() {
    local pid="$1"
    [ "$OnlyGaming" = false ] && return 0

    # 1. Known Blacklist (Non-gaming GPU heavy apps)
    local proc_comm=$(ps -p "$pid" -o comm= 2>/dev/null)
    case "$proc_comm" in
        Xorg|gnome-shell|kwin_wayland|sway|wayland|Xwayland) return 1 ;;
        chrome|firefox|brave|msedge|opera|browser) return 1 ;;
        steamwebhelper|Discord|slack|teams|obs|obs64) return 1 ;;
    esac

    # 2. Gaming Environment Variables
    if [ -r "/proc/$pid/environ" ]; then
        # Check for Steam, Proton, Lutris, Heroic markers
        if tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | grep -qE "^(STEAM_COMPAT_APP_ID|STEAM_GAME_ID|LUTRIS_GAME_ID|HEROIC_APP_NAME|PROTON_VER|WINEPREFIX)="; then
            return 0
        fi
    fi

    # 3. Heuristics (Wine/Proton processes, Game executables)
    local proc_args=$(ps -fp "$pid" -o args= 2>/dev/null)
    if echo "$proc_args" | grep -qiE "\.exe|wine|proton|reaper|Game\.x86_64|UnityPlayer"; then
        return 0
    fi

    # 4. Check Parent Processes (up to 3 levels)
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

# 5. Optimization Function
run_optimization() {
    local node_free_kb=0
    [ "$numa_node_id" -ge 0 ] && node_free_kb=$(get_node_free_kb "$numa_node_id")

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

        if [ "$current_normalized_mask" != "$target_normalized_mask" ]; then
            taskset -pc "$final_cpu_mask" "$pid" > /dev/null 2>&1

            if [ "$StrictMem" = true ]; then
                numactl --membind="$numa_node_id" -p "$pid" > /dev/null 2>&1
            else
                numactl --preferred="$numa_node_id" -p "$pid" > /dev/null 2>&1
            fi

            local process_rss_kb=$(awk '/VmRSS/ {print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)
            local safety_margin_kb=524288

            local proc_comm=$(ps -p "$pid" -o comm=)

            local full_proc_cmd=$(ps -fp "$pid" -o args= | tail -n 1)
            [ -z "$full_proc_cmd" ] && full_proc_cmd="[Hidden or Exited]"

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

            if [ "$node_free_kb" -gt $((process_rss_kb + safety_margin_kb)) ]; then
                if migratepages "$pid" all "$numa_node_id" > /dev/null 2>&1; then
                    status_msg="OPTIMIZED & MOVED"
                    node_free_kb=$((node_free_kb - process_rss_kb))
                    notify_user "$proc_comm(PID: $pid): Optimized (Node $numa_node_id)" "$simplified_cmd\n\nCPU affinity set and memory migrated" "dialog-information"
                else
                    status_msg="OPTIMIZED (MOVE FAILED)"
                    notify_user "$proc_comm(PID: $pid): Migration Failed (Node $numa_node_id)" "$simplified_cmd\n\nCPU affinity set, but memory migration failed" "dialog-warning"
                fi
            else
                status_msg="OPTIMIZED (NODE FULL)"
                notify_user "$proc_comm(PID: $pid): Node $numa_node_id Full " "$simplified_cmd\n\nCPU affinity set, but NUMA node is full" "dialog-warning"
            fi

            printf "%-8s | %-15s | %-25s | %s\n" "$pid" "$proc_comm" "$status_msg" "$full_proc_cmd"
        fi
    done
}

# 6. Execution Loop
if [ "$DaemonMode" = true ]; then
    while true; do
        run_optimization
        sleep "$SleepInterval"
    done
else
    run_optimization
    echo "--------------------------------------------------------"
    echo "Optimization complete."
fi
