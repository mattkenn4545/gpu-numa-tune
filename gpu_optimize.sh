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
        set_sysctl "kernel.split_lock_mitigate" "0" "Execution Latency"
        set_sysctl "kernel.sched_migration_cost_ns" "5000000" "Scheduler"
        set_sysctl "net.core.netdev_max_backlog" "5000" "Network"

        echo "--> System tuning complete."
        echo "--------------------------------------------------------"
    else
        echo "--------------------------------------------------------"
        echo "WARNING: Not running as root. Latency tuning skipped."
        echo "--------------------------------------------------------"
        sleep 1
    fi
}

system_tune

# 1. Argument Parsing
while [[ "$1" =~ ^- ]]; do
    case $1 in
        -p|--physical-only) UseHt=false; shift ;;
        -d|--daemon) DaemonMode=true; shift ;;
        -s|--strict) StrictMem=true; shift ;;
        *) echo "Unknown option: $1" ; exit 1 ;;
    esac
done

# 2. Identify GPUs (NVIDIA, AMD, Intel)
mapfile -t all_vga_devices < <(lspci -D | grep -iE 'vga|3d')
gpu_index_arg=${1:-0}
pci_addr=$(echo "${all_vga_devices[$gpu_index_arg]}" | awk '{print $1}')

if [ -z "$pci_addr" ]; then
    echo "Error: GPU index $gpu_index_arg not found."
    exit 1
fi

# 3. Identify NUMA Node and CPU List
device_sys_dir="/sys/bus/pci/devices/$pci_addr"
numa_node_id=$(cat "$device_sys_dir/numa_node")
raw_cpu_list=$(cat "$device_sys_dir/local_cpulist")

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

target_normalized_mask=$(normalize_affinity "$final_cpu_mask")
mem_policy_label=$([ "$StrictMem" = true ] && echo "Strict (OOM Risk)" || echo "Preferred (Safe)")

# --- Startup Output ---
echo "OPTIMIZING GPU   : $pci_addr"
echo "MODEL            :$(lspci -s "$pci_addr" | cut -d: -f3)"
echo "NUMA NODE        : $numa_node_id"
echo "CPU TARGETS      : $final_cpu_mask"
echo "MEM POLICY       : $mem_policy_label"
echo "MODE             : $( [ "$DaemonMode" = true ] && echo "Daemon" || echo "Single-run" )"
echo "--------------------------------------------------------"
printf "%-8s | %-15s | %-25s | %s\n" "PID" "EXE" "STATUS" "COMMAND"
echo "--------------------------------------------------------"

# 5. Optimization Function
run_optimization() {
    local node_free_kb=$(get_node_free_kb "$numa_node_id")
    # Cross-vendor PID detection
    local gpu_pids=$(fuser /dev/dri/* /dev/nvidia* 2>/dev/null | tr ' ' '\n' | sort -u)

    for pid in $gpu_pids; do
        if [ "$pid" -lt 100 ] || [ ! -d "/proc/$pid" ]; then continue; fi
        if [ "$EUID" -ne 0 ] && [ ! -O "/proc/$pid" ]; then continue; fi

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

            if [ "$node_free_kb" -gt $((process_rss_kb + safety_margin_kb)) ]; then
                migratepages "$pid" all "$numa_node_id" > /dev/null 2>&1
                status_msg="OPTIMIZED & MOVED"
                node_free_kb=$((node_free_kb - process_rss_kb))
            else
                status_msg="OPTIMIZED (NODE FULL)"
            fi

            local proc_comm=$(ps -p "$pid" -o comm=)
            [[ "$proc_comm" == "Xorg" || "$proc_comm" == "gnome-shell" || "$proc_comm" == "kwin_wayland" ]] && continue

            local full_proc_cmd=$(ps -fp "$pid" -o args= | tail -n 1)
            [ -z "$full_proc_cmd" ] && full_proc_cmd="[Hidden or Exited]"

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
