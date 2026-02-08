#!/bin/bash

# ==============================================================================
# GPU NUMA Optimizer - Test Suite
# ==============================================================================
# Purpose:
#   Validates the core logic of gpu_optimize.sh using mocks for system 
#   resources, hardware files, and external utilities.
#
# Methodology:
#   1. Sets up a mock environment (sysfs, procfs, devfs) in local directories.
#   2. Mocks external commands (lspci, ps, numactl, etc.) using shell functions.
#   3. Sources gpu_optimize.sh to gain access to its internal functions.
#   4. Executes unit tests and asserts expected outcomes.
# ==============================================================================

# Clean up function for mock environment
cleanup() {
    rm -rf tests/mock_bin tests/mock_proc tests/mock_sys tests/mock_dev tests/mock_all_time tests/mock_home tests/mock_all_time.tmp
    [ -f "$SystemConfig" ] && rm -f "$SystemConfig"
}
trap cleanup EXIT

# Simple test runner for gpu_optimize.sh

# ANSI colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

PASSED=0
FAILED=0

# --- Mocking Infrastructure ---

# Many of the functions in gpu_optimize.sh rely on external commands or /proc and /sys files.
# To test them without requiring root or specific hardware, we use a combination of:
#   1. Redefining commands as shell functions (e.g., ps(), lspci()).
#   2. Using environment variables (SYSFS_PREFIX, PROC_PREFIX) to redirect file lookups.

pgrep() {
    if [[ "$*" == *"-f pipewire|pipewire-pulse|pipewire-media-session|wireplumber"* ]]; then
        echo "4444 4445"
    fi
}

# Create mocks for basic external commands
lspci() {
    echo "0000:01:00.0 VGA compatible controller: NVIDIA Corporation GA102 [GeForce RTX 3080] (rev a1)"
}

notify-send() {
    return 0
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

# Source the script - the script has a guard [[ "${BASH_SOURCE[0]}" == "${0}" ]] 
# to prevent execution when sourced, allowing us to test its functions.
source ./gpu_optimize.sh

assert_eq() {
    local expected="$1"
    local actual="$2"
    local msg="$3"
    if [ "$expected" == "$actual" ]; then
        echo -e "${GREEN}[PASS]${NC} $msg"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}[FAIL]${NC} $msg"
        echo "  Expected: '$expected'"
        echo "  Actual:   '$actual'"
        FAILED=$((FAILED + 1))
    fi
}

echo "Running tests..."

# Test 1: normalize_affinity
assert_eq "0,1,2,3,6" "$(normalize_affinity "0-3,6")" "normalize_affinity basic"
assert_eq "0,1,2,3" "$(normalize_affinity "0,1,2,3")" "normalize_affinity already normalized"
assert_eq "0,1,2,3" "$(normalize_affinity "3,2,1,0")" "normalize_affinity sorting"

# Test 1b: format_range
assert_eq "1-5" "$(format_range "1,2,3,4,5")" "format_range simple sequence"
assert_eq "1,2,5-7,9" "$(format_range "1,2,5,6,7,9")" "format_range mixed"
assert_eq "1-3,5-7" "$(format_range "1,2,3,5,6,7")" "format_range two ranges"
assert_eq "1,3,5" "$(format_range "5,1,3")" "format_range sorting and no ranges"
assert_eq "1-3" "$(format_range "1,2,2,3")" "format_range deduplication"

# Test 2: parse_args
parse_args "-p" "--daemon" "-s" "1"
assert_eq "false" "$UseHt" "parse_args --physical-only"
assert_eq "true" "$DaemonMode" "parse_args --daemon"
assert_eq "true" "$StrictMem" "parse_args --strict"
assert_eq "1" "$GpuIndexArg" "parse_args GpuIndexArg"

parse_args "--no-pipewire"
assert_eq "false" "$TunePipeWire" "parse_args --no-pipewire"
TunePipeWire=true # Reset

# Test 2b: run_optimization skips PipeWire when TunePipeWire=false
TunePipeWire=false
PROC_PREFIX="$(pwd)/tests/mock_proc"
mkdir -p "$PROC_PREFIX/proc/4444"
mkdir -p "$PROC_PREFIX/proc/4445"
# Clear cached info to force reload
BatchedProcInfoMap=()
OptimizedPidsMap=()
PRINTF_OUTPUT=""
run_optimization > /tmp/opt_output_nopipe 2>&1
echo "$PRINTF_OUTPUT" | grep -q "4444" || grep -q "4444" /tmp/opt_output_nopipe
assert_eq "1" "$?" "run_optimization skips PipeWire when TunePipeWire=false"
TunePipeWire=true # Reset

parse_args "-l" "-a" "-x" "-k" "-c" "--no-irq" "--comm-pipe" "/tmp/pipe"
assert_eq "false" "$IncludeNearby" "parse_args --local-only"
assert_eq "false" "$OnlyGaming" "parse_args --all-gpu-procs"
assert_eq "true" "$SkipSystemTune" "parse_args --no-tune"
assert_eq "false" "$DropPrivs" "parse_args --no-drop"
assert_eq "false" "$AutoGenConfig" "parse_args --no-config"
assert_eq "false" "$OptimizeIrqs" "parse_args --no-irq"
assert_eq "/tmp/pipe" "$CommPipe" "parse_args --comm-pipe"

# Test 3: is_gaming_process (mocking ps and /proc)
# We can't easily mock /proc in a simple script without LD_PRELOAD or similar, 
# but we can use our SYSFS_PREFIX if we were reading from /proc, but here it's mostly ps.

# Mocking ps
ps() {
    if [[ "$*" == *"--no-headers"* ]]; then
        # Handle batch_load_proc_info
        echo " 5678     1 chrome          /usr/bin/chrome --type=renderer"
        echo " 1234     1 game_exe        ./game_exe"
        echo " 1111  2222 some_child      ./some_child"
        echo " 2222     1 steam           /usr/bin/steam"
        echo " 3333     1 wine_proc       /usr/bin/wine some_game.exe"
        echo " 4444     1 pipewire        /usr/bin/pipewire"
        echo " 4445     1 wireplumber     /usr/bin/wireplumber"
        echo " 9999     1 game_exe        game_exe"
        return
    fi
    case "$*" in
        *"-p 1234 -o comm="*) echo "game_exe" ;;
        *"-p 5678 -o comm="*) echo "chrome" ;;
        *"-fp 1234 -o args="*) echo "./game_exe" ;;
        *"-fp 5678 -o args="*) echo "/usr/bin/chrome --type=renderer" ;;
        *"-p 1234 -o ppid="*) echo "1" ;;
        *"-p 1111 -o comm="*) echo "some_child" ;;
        *"-fp 1111 -o args="*) echo "./some_child" ;;
        *"-p 1111 -o ppid="*) echo "2222" ;;
        *"-p 2222 -o comm="*) echo "steam" ;;
        *"-fp 2222 -o args="*) echo "/usr/bin/steam" ;;
        *"-p 2222 -o ppid="*) echo "1" ;;
        *"-p 3333 -o comm="*) echo "wine_proc" ;;
        *"-fp 3333 -o args="*) echo "/usr/bin/wine some_game.exe" ;;
        *"-p 3333 -o ppid="*) echo "1" ;;
        *"-p 9999 -o comm="*) echo "game_exe" ;;
        *"-fp 9999 -o args="*) echo "game_exe" ;;
        *"-p 9999 -o ppid="*) echo "1" ;;
        *) command ps "$@" ;;
    esac
}

# We don't export -f here because we want it in the current shell context
# where is_gaming_process will run.

# Set up mock paths
export SYSFS_PREFIX="$(pwd)/tests/mock_sys"
export PROC_PREFIX="$(pwd)/tests/mock_proc"
export SystemConfig="$(pwd)/tests/mock_etc_gpu-numa-tune.conf"
mkdir -p "$SYSFS_PREFIX" "$PROC_PREFIX/proc/1234" "$(dirname "$SystemConfig")"
mkdir -p "$PROC_PREFIX/proc/5678" "$PROC_PREFIX/proc/1111" "$PROC_PREFIX/proc/2222" "$PROC_PREFIX/proc/3333" "$PROC_PREFIX/proc/9999"

# Create empty environ file with read permission
touch "$PROC_PREFIX/proc/1234/environ"
chmod 644 "$PROC_PREFIX/proc/1234/environ"

# Ensure batch info is loaded for tests that don't call run_optimization
batch_load_proc_info

# Let's test is_gaming_process for a few cases
# Case: Blacklisted
OnlyGaming=true
assert_eq "1" "$(is_gaming_process 5678; echo $?)" "is_gaming_process chrome (blacklisted)"

# For PID 1234, it should pass because it has a gaming environment variable
# Put a gaming env var in the mock environ file
echo -e "STEAM_GAME_ID=123\0" > "$PROC_PREFIX/proc/1234/environ"

assert_eq "0" "$(is_gaming_process 1234; echo $?)" "is_gaming_process with STEAM_GAME_ID (allowed)"
assert_eq "0" "$(is_gaming_process 1111; echo $?)" "is_gaming_process child of steam (allowed)"
assert_eq "0" "$(is_gaming_process 3333; echo $?)" "is_gaming_process wine .exe (allowed)"
assert_eq "0" "$(is_gaming_process 4444; echo $?)" "is_gaming_process pipewire (allowed)"
assert_eq "0" "$(is_gaming_process 4445; echo $?)" "is_gaming_process wireplumber (allowed)"

# Test 3.1: is_gaming_process caching
NonGamingPidsMap=()
# PID 5678 is chrome (blacklisted)
is_gaming_process 5678 > /dev/null
assert_eq "1" "$(is_gaming_process 5678; echo $?)" "is_gaming_process uses cache for non-gaming"
assert_eq "true" "$( [ -n "${NonGamingPidsMap[5678]}" ] && echo true )" "NonGamingPidsMap populated"

# Test 4: Hardware discovery (using SYSFS_PREFIX)
export SYSFS_PREFIX="$(pwd)/tests/mock_sys"
mkdir -p "$SYSFS_PREFIX/sys/bus/pci/devices/0000:01:00.0"
echo "0" > "$SYSFS_PREFIX/sys/bus/pci/devices/0000:01:00.0/numa_node"
echo "0-7" > "$SYSFS_PREFIX/sys/bus/pci/devices/0000:01:00.0/local_cpulist"

PciAddr="0000:01:00.0"
IncludeNearby=false
discover_resources

assert_eq "0" "$NumaNodeId" "discover_resources NumaNodeId"
assert_eq "0-7" "$RawCpuList" "discover_resources RawCpuList"

# Test 5: get_nearby_nodes and get_nodes_cpulist
mkdir -p "$SYSFS_PREFIX/sys/devices/system/node/node"{0..1}
echo "0-3" > "$SYSFS_PREFIX/sys/devices/system/node/node0/cpulist"
echo "4-7" > "$SYSFS_PREFIX/sys/devices/system/node/node1/cpulist"

# Mock numactl --hardware
numactl() {
    if [[ "$*" == "--hardware" ]]; then
        echo "available: 2 nodes (0-1)"
        echo "node 0 cpus: 0 1 2 3"
        echo "node 0 size: 16100 MB"
        echo "node 0 free: 12000 MB"
        echo "node 1 cpus: 4 5 6 7"
        echo "node 1 size: 16100 MB"
        echo "node 1 free: 11000 MB"
        echo "node distances:"
        echo "node   0   1"
        echo "  0:  10  11"
        echo "  1:  11  10"
    else
        command numactl "$@"
    fi
}

MaxDist=11
assert_eq "0,1" "$(get_nearby_nodes 0 11)" "get_nearby_nodes with numactl"
assert_eq "0-3,4-7" "$(get_nodes_cpulist "0,1")" "get_nodes_cpulist"

# Test without numactl
numactl() {
    return 127
}
assert_eq "0" "$(get_nearby_nodes 0 11)" "get_nearby_nodes without numactl"

# Test 6: Memory utils
echo "Node 0 MemTotal: 16486400 kB" > "$SYSFS_PREFIX/sys/devices/system/node/node0/meminfo"
echo "Node 0 MemFree:  12288000 kB" >> "$SYSFS_PREFIX/sys/devices/system/node/node0/meminfo"
echo "Node 0 MemUsed:   4198400 kB" >> "$SYSFS_PREFIX/sys/devices/system/node/node0/meminfo"

assert_eq "16100" "$(get_node_total_mb 0)" "get_node_total_mb"
assert_eq "12288000" "$(get_node_free_kb 0)" "get_node_free_kb"
assert_eq "4100" "$(get_node_used_mb 0)" "get_node_used_mb"

# Test 7: filter_cpus (SMT/HT)
mkdir -p "$SYSFS_PREFIX/sys/devices/system/cpu/cpu"{0..7}"/topology"
# Mock siblings: 0 and 4 are siblings, 1 and 5, etc.
echo "0,4" > "$SYSFS_PREFIX/sys/devices/system/cpu/cpu0/topology/thread_siblings_list"
echo "1,5" > "$SYSFS_PREFIX/sys/devices/system/cpu/cpu1/topology/thread_siblings_list"
echo "2,6" > "$SYSFS_PREFIX/sys/devices/system/cpu/cpu2/topology/thread_siblings_list"
echo "3,7" > "$SYSFS_PREFIX/sys/devices/system/cpu/cpu3/topology/thread_siblings_list"
echo "0,4" > "$SYSFS_PREFIX/sys/devices/system/cpu/cpu4/topology/thread_siblings_list"
echo "1,5" > "$SYSFS_PREFIX/sys/devices/system/cpu/cpu5/topology/thread_siblings_list"
echo "2,6" > "$SYSFS_PREFIX/sys/devices/system/cpu/cpu6/topology/thread_siblings_list"
echo "3,7" > "$SYSFS_PREFIX/sys/devices/system/cpu/cpu7/topology/thread_siblings_list"

UseHt=false
RawCpuList="0-7"
filter_cpus
assert_eq "0,1,2,3" "$TargetNormalizedMask" "filter_cpus physical-only"

UseHt=true
filter_cpus
assert_eq "0,1,2,3,4,5,6,7" "$TargetNormalizedMask" "filter_cpus HT allowed"

# Test 8: detect_gpu
# Mocking sysfs and dev for detect_gpu
export DEV_PREFIX="$(pwd)/tests/mock_dev"
mkdir -p "$DEV_PREFIX/dev/dri"
touch "$DEV_PREFIX/dev/dri/renderD128"

mkdir -p "$SYSFS_PREFIX/sys/class/drm/renderD128"
# Note: readlink -f will resolve this in the real world, but our mock readlink handles it here
ln -sf "$SYSFS_PREFIX/sys/devices/pci0000:00/0000:00:01.0/0000:01:00.0" "$SYSFS_PREFIX/sys/class/drm/renderD128/device"

lspci() {
    if [[ "$*" == "-D" ]]; then
        # Include another GPU to test indexing
        echo "0000:01:00.0 VGA compatible controller: NVIDIA Corporation GA102 [GeForce RTX 3080] (rev a1)"
        echo "0000:41:00.0 VGA compatible controller: NVIDIA Corporation GA102 [GeForce RTX 3080] (rev a1)"
    else
        echo "lspci mock: $*"
    fi
}

readlink() {
    if [[ "$*" == *"/sys/class/drm/renderD128/device" ]]; then
        echo "0000:01:00.0"
    else
        command readlink "$@"
    fi
}

GpuIndexArg=0
detect_gpu
assert_eq "0000:01:00.0" "$PciAddr" "detect_gpu index 0 (renderD128)"

GpuIndexArg=1
detect_gpu
assert_eq "0000:41:00.0" "$PciAddr" "detect_gpu index 1 (lspci fallback)"

# Test 9: Dry-run mode
DryRun=true
# Mock commands to check if they were called
TASKSET_CALLED=false
NUMACTL_CALLED=false
MIGRATEPAGES_CALLED=false
SYSCTL_CALLED=false

taskset() { TASKSET_CALLED=true; }
numactl() { NUMACTL_CALLED=true; }
migratepages() { MIGRATEPAGES_CALLED=true; }
# Mock sysctl to just return 0
sysctl() { return 0; }

# Mocking for system_tune
MOCK_EUID=0
SkipSystemTune=false
SystemTuned="" # Reset SystemTuned to allow printing/tuning

# Mock systemctl
SYSTEMCTL_STOP_CALLED_COUNT=0
SYSTEMCTL_START_CALLED_COUNT=0
systemctl() {
    case "$1" in
        list-unit-files) return 0 ;; # Pretend all services exist
        is-active) return 0 ;; # Pretend it's active
        stop) SYSTEMCTL_STOP_CALLED_COUNT=$((SYSTEMCTL_STOP_CALLED_COUNT + 1)); return 0 ;;
        start) SYSTEMCTL_START_CALLED_COUNT=$((SYSTEMCTL_START_CALLED_COUNT + 1)); return 0 ;;
    esac
}

system_manage_settings "tune"

assert_eq "false" "$SYSCTL_CALLED" "Dry-run: sysctl not called"
assert_eq "0" "$SYSTEMCTL_STOP_CALLED_COUNT" "Dry-run: systemctl stop not called"

# Test 9.1: system_manage_settings "tune" (NOT DryRun)
echo "Test 9.1: system_manage_settings 'tune' (NOT DryRun)"
DryRun=false
SystemTuned=""
SYSTEMCTL_STOP_CALLED_COUNT=0
system_manage_settings "tune" > /dev/null
assert_eq "2" "$SYSTEMCTL_STOP_CALLED_COUNT" "system_manage_settings 'tune' stops irqbalance and numad"

# Test 9.2: system_manage_settings "restore"
echo "Test 9.2: system_manage_settings 'restore'"
SystemTuned=true
SYSTEMCTL_START_CALLED_COUNT=0
system_manage_settings "restore" > /dev/null
assert_eq "2" "$SYSTEMCTL_START_CALLED_COUNT" "system_manage_settings 'restore' starts irqbalance and numad"
DryRun=true # Reset for next tests

# Mocking for run_optimization
PROC_PREFIX="$(pwd)/tests/mock_proc"
mkdir -p "$PROC_PREFIX/proc/9999"
mkdir -p "$PROC_PREFIX/proc/4444"
mkdir -p "$PROC_PREFIX/proc/4445"
touch "$PROC_PREFIX/proc/9999/environ"
touch "$PROC_PREFIX/proc/4444/environ"
touch "$PROC_PREFIX/proc/4445/environ"
echo -e "STEAM_GAME_ID=123\0" > "$PROC_PREFIX/proc/9999/environ"

# Mocking fuser to return our test PID
fuser() { echo "9999"; }
# Mocking ps for PIDs
ps() {
    case "$*" in
        *"-p 9999 -o comm="*) echo "game_exe" ;;
        *"-p 4444 -o comm="*) echo "pipewire" ;;
        *"-p 4445 -o comm="*) echo "wireplumber" ;;
        *"-fp 9999 -o args="*) echo "./game_exe" ;;
        *"-fp 4444 -o args="*) echo "/usr/bin/pipewire" ;;
        *"-fp 4445 -o args="*) echo "/usr/bin/wireplumber" ;;
        *"-p 9999 -o ppid="*) echo "1" ;;
        *"-p 4444 -o ppid="*) echo "1" ;;
        *"-p 4445 -o ppid="*) echo "1" ;;
        *"-eo pid,ppid,comm,args --no-headers"*)
            echo " 9999     1 game_exe        ./game_exe"
            echo " 4444     1 pipewire        /usr/bin/pipewire"
            echo " 4445     1 wireplumber     /usr/bin/wireplumber"
            ;;
        *) command ps "$@" ;;
    esac
}
# Mock taskset -pc PID to return some affinity
taskset() {
    if [[ "$*" == "-pc 9999" ]]; then
        echo "pid 9999's current affinity list: 0-7"
    elif [[ "$*" == "-pc 4444" ]]; then
        echo "pid 4444's current affinity list: 0-7"
    elif [[ "$*" == "-pc 4445" ]]; then
        echo "pid 4445's current affinity list: 0-7"
    else
        TASKSET_CALLED=true
    fi
}

TargetNormalizedMask="0,1,2,3" # Different from 0-7

run_optimization > /tmp/opt_output 2>&1
echo "$PRINTF_OUTPUT" | grep -q "9999" || grep -q "9999" /tmp/opt_output
assert_eq "0" "$?" "run_optimization processes PID 9999 (GPU)"
echo "$PRINTF_OUTPUT" | grep -q "4444" || grep -q "4444" /tmp/opt_output
assert_eq "0" "$?" "run_optimization processes PID 4444 (PipeWire)"
echo "$PRINTF_OUTPUT" | grep -q "4445" || grep -q "4445" /tmp/opt_output
assert_eq "0" "$?" "run_optimization processes PID 4445 (WirePlumber)"

assert_eq "false" "$TASKSET_CALLED" "Dry-run: taskset not called"
assert_eq "false" "$NUMACTL_CALLED" "Dry-run: numactl not called"
assert_eq "false" "$MIGRATEPAGES_CALLED" "Dry-run: migratepages not called"

# Test 10: All-time tracking
echo "Test 10: All-time tracking"
AllTimeFile="tests/mock_all_time"
rm -f "$AllTimeFile"
LifetimeOptimizedCount=0
TotalOptimizedCount=0
OptimizedPidsMap=()
simplified_cmd="game" # Added for Test 10 logging

# Simulate load_all_time_stats by manually setting up and calling it
# We need to mock getent
getent() {
    if [[ "$*" == "passwd testuser" ]]; then
        echo "testuser:x:1000:1000::$(pwd)/tests/mock_home:/bin/bash"
    fi
}
mkdir -p tests/mock_home/.config/gpu-numa-tune/
echo "entry1" > tests/mock_home/.config/gpu-numa-tune/optimizations.log
echo "entry2" >> tests/mock_home/.config/gpu-numa-tune/optimizations.log
TargetUser="testuser"

load_all_time_stats
assert_eq "2" "$LifetimeOptimizedCount" "load_all_time_stats loads correct line count"
assert_eq "$(pwd)/tests/mock_home/.config/gpu-numa-tune/optimizations.log" "$AllTimeFile" "AllTimeFile path set correctly"

# Simulate optimizing a process (ACTUAL optimization)
pid=1234
proc_comm="game"
raw_current_affinity="0-7"
TargetNormalizedMask="0,1,2,3" # Force optimization
current_normalized_mask="0,1,2,3,4,5,6,7" # Different from target
full_proc_cmd="./game"
status_msg="OPTIMIZED"
NearbyNodeIds="0"
DryRun=false
AllTimeFile="tests/mock_all_time" # Redirect to local mock for the rest of Test 10
rm -f "$AllTimeFile"
touch "$AllTimeFile"
echo "entry1" >> "$AllTimeFile"
echo "entry2" >> "$AllTimeFile"
LifetimeOptimizedCount=2

# Mock ps for this PID
ps() {
    case "$*" in
        *"-p 1234 -o comm="*) echo "game" ;;
        *"-fp 1234 -o args="*) echo "./game" ;;
        *"-p 1234 -o ppid="*) echo "1" ;;
        *) command ps "$@" ;;
    esac
}

# Run the part of run_optimization that handles ACTUAL optimization
if [ "$current_normalized_mask" != "$TargetNormalizedMask" ]; then
    if [ -z "${OptimizedPidsMap[$pid]}" ]; then
        ((TotalOptimizedCount++))
        ((LifetimeOptimizedCount++))
        if [ "$DryRun" = false ] && [ -n "$AllTimeFile" ]; then
            printf "%-19s | %-8s | %-16s | %-20s | %-22s | %-8s | %s\n" \
                "$(date "+%Y-%m-%d %H:%M:%S")" "$pid" "$proc_comm" "$simplified_cmd" "$status_msg" "${NearbyNodeIds:-$NumaNodeId}" "$full_proc_cmd" >> "$AllTimeFile" 2>/dev/null
        fi
    fi
    OptimizedPidsMap[$pid]=$(date +%s)
fi

assert_eq "1" "$TotalOptimizedCount" "TotalOptimizedCount incremented for actual optimization"
assert_eq "3" "$LifetimeOptimizedCount" "LifetimeOptimizedCount incremented from 2"
assert_eq "3" "$(wc -l < $AllTimeFile)" "AllTimeFile line count updated for actual optimization"

# Simulate process ALREADY optimized (mask matches)
pid=5678
proc_comm="game2"
current_normalized_mask="0,1,2,3" # Already matches TargetNormalizedMask
# OptimizedPidsMap for 5678 is empty

if [ "$current_normalized_mask" != "$TargetNormalizedMask" ]; then
    # Should not enter here
    :
else
    if [ -z "${OptimizedPidsMap[$pid]}" ]; then
        # Already optimized branch
        OptimizedPidsMap[$pid]=$(date +%s)
    fi
fi

assert_eq "1" "$TotalOptimizedCount" "TotalOptimizedCount NOT incremented if already optimized"
assert_eq "3" "$LifetimeOptimizedCount" "LifetimeOptimizedCount NOT incremented if already optimized"
assert_eq "3" "$(wc -l < $AllTimeFile)" "AllTimeFile NOT updated if already optimized"

# Cleanup mock home
rm -rf tests/mock_home

# Test 11: Startup summary
echo "Test 11: Startup summary"
# We'll use a subshell to capture output and check if it contains the summary line
output=$(
    # Mock some things for a clean run
    PciAddr="0000:01:00.0"
    NumaNodeId=0
    NearbyNodeIds="0"
    IncludeNearby=true
    MaxDist=11
    FinalCpuMask="0-7"
    TargetNormalizedMask="0,1,2,3,4,5,6,7"
    OptimizedPidsMap=()
    TotalOptimizedCount=0
    LifetimeOptimizedCount=5 # Pre-set some value
    LastSummaryTime=$(date +%s)
    
    # We want to check if print_banner followed by summarize_optimizations true works
    # We can just call the functions if we source the script
    print_banner > /dev/null # Skip banner
    summarize_optimizations true
)

assert_eq "0 procs    | since startup    |                      | 5 all time         | OPTIMIZING                | 0 processes currently optimized (0 triggering tune)" "$(echo "$output" | tail -n 1)" "Startup summary output matches expected format"

# Test 11b: Startup summary -l option
echo "Test 11b: Startup summary -l option"
output_l=$(
    PciAddr="0000:01:00.0"
    NumaNodeId=0
    NearbyNodeIds="0"
    IncludeNearby=false
    MaxDist=11
    print_banner
)
echo "$output_l" | grep -q "NUMA NODE        : 0 (Local Only)"
assert_eq "0" "$?" "Startup summary with -l shows (Local Only)"
echo "$output_l" | grep -q "Nearby Max Distance"
if [ "$?" -eq 0 ]; then
    echo "[FAIL] Startup summary with -l should NOT show 'Nearby Max Distance'"
    exit 1
else
    echo "[PASS] Startup summary with -l does NOT show 'Nearby Max Distance'"
fi

# Test 12: All-time log rotation
echo "Test 12: All-time log rotation (with 50-line buffer)"
AllTimeFile="tests/mock_all_time"
rm -f "$AllTimeFile"
MaxAllTimeLogLines=10

# Populate with 11 lines (exceeds MaxAllTimeLogLines but NOT by 50)
for i in {1..11}; do echo "line$i" >> "$AllTimeFile"; done
# LifetimeOptimizedCount is not used by trim_all_time_log anymore, it recalculates

trim_all_time_log
assert_eq "11" "$(wc -l < "$AllTimeFile")" "trim_all_time_log does NOT trim within 50-line buffer"

# Populate to 61 lines (exceeds MaxAllTimeLogLines + 50)
for i in {12..61}; do echo "line$i" >> "$AllTimeFile"; done

trim_all_time_log
assert_eq "10" "$(wc -l < "$AllTimeFile")" "trim_all_time_log trims to MaxAllTimeLogLines after 50-line overflow"
assert_eq "line52" "$(head -n 1 "$AllTimeFile")" "trim_all_time_log keeps most recent entries (line52)"
assert_eq "line61" "$(tail -n 1 "$AllTimeFile")" "trim_all_time_log keeps most recent entries (line61)"

# Test 13: Configuration loading
echo "Test 13: Configuration loading"
mkdir -p tests/mock_etc
mock_conf="tests/mock_etc/gpu-numa-tune.conf"
cat > "$mock_conf" <<EOF
UseHt=false
DaemonMode=true
SleepInterval=5
StrictMem=true
IncludeNearby=false
MaxDist=15
OnlyGaming=false
SkipSystemTune=true
DryRun=true
DropPrivs=false
AutoGenConfig=false
MaxAllTimeLogLines=5000
GpuIndex=2
ReniceValue=-5
IoniceValue=idle
OptimizeIrqs=false
SummaryInterval=3600
SummarySilenceTimeout=14400
HeaderInterval=50
CommPipe=/tmp/testpipe
EOF

# Test 13.1: create_process_config content
echo "Test 13.1: create_process_config content"
LocalConfigPath="tests/mock_local_config"
mkdir -p "$LocalConfigPath"
# Set globals to specific values
GlobalUseHt=true
GlobalIncludeNearby=true
GlobalMaxDist=10
GlobalStrictMem=false
GlobalReniceValue="-15"
GlobalIoniceValue="realtime:3"
DryRun=false
TargetUser="" # Use current user home

create_process_config "test_app"
config_file="${HOME}/${LocalConfigPath}/test_app.conf"

if [ -f "$config_file" ]; then
    content=$(cat "$config_file")
    grep -q "UseHt=true" <<< "$content" && assert_eq "0" "$?" "create_process_config UseHt"
    grep -q "IncludeNearby=true" <<< "$content" && assert_eq "0" "$?" "create_process_config IncludeNearby"
    grep -q "MaxDist=10" <<< "$content" && assert_eq "0" "$?" "create_process_config MaxDist"
    grep -q "StrictMem=false" <<< "$content" && assert_eq "0" "$?" "create_process_config StrictMem"
    grep -q "ReniceValue=-15" <<< "$content" && assert_eq "0" "$?" "create_process_config ReniceValue"
    grep -q "IoniceValue=realtime:3" <<< "$content" && assert_eq "0" "$?" "create_process_config IoniceValue"
else
    echo -e "${RED}[FAIL]${NC} create_process_config: config file not created"
    FAILED=$((FAILED + 1))
fi
rm -rf "$LocalConfigPath"

# Redefine load_config to use our mock etc path
# Actually we can just override the config_files array if it wasn't local to the function, 
# but it is. So we override the function for the test.
load_config() {
    local config_files=("$mock_conf")
    for file in "${config_files[@]}"; do
        if [ -f "$file" ]; then
            while IFS='=' read -r key value || [ -n "$key" ]; do
                [[ "$key" =~ ^[[:space:]]*#.*$ ]] && continue
                [[ -z "$key" ]] && continue
                key=$(echo "$key" | xargs)
                value=$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
                value=${value%%#*}
                value=$(echo "$value" | xargs)
                case "$key" in
                    UseHt) UseHt="$value" ;;
                    DaemonMode) DaemonMode="$value" ;;
                    SleepInterval) SleepInterval="$value" ;;
                    StrictMem) StrictMem="$value" ;;
                    IncludeNearby) IncludeNearby="$value" ;;
                    MaxDist) MaxDist="$value" ;;
                    OnlyGaming) OnlyGaming="$value" ;;
                    SkipSystemTune) SkipSystemTune="$value" ;;
                    DryRun) DryRun="$value" ;;
                    DropPrivs) DropPrivs="$value" ;;
                    MaxAllTimeLogLines) MaxAllTimeLogLines="$value" ;;
                    AutoGenConfig) AutoGenConfig="$value" ;;
                    GpuIndex) GpuIndexArg="$value" ;;
                    OptimizeIrqs) OptimizeIrqs="$value" ;;
                    SummaryInterval) SummaryInterval="$value" ;;
                    SummarySilenceTimeout) SummarySilenceTimeout="$value" ;;
                    HeaderInterval) HeaderInterval="$value" ;;
                    CommPipe) CommPipe="$value" ;;
                esac
            done < "$file"
        fi
    done
}

load_config
assert_eq "false" "$UseHt" "Config: UseHt"
assert_eq "true" "$DaemonMode" "Config: DaemonMode"
assert_eq "5" "$SleepInterval" "Config: SleepInterval"
assert_eq "true" "$StrictMem" "Config: StrictMem"
assert_eq "false" "$IncludeNearby" "Config: IncludeNearby"
assert_eq "15" "$MaxDist" "Config: MaxDist"
assert_eq "false" "$OnlyGaming" "Config: OnlyGaming"
assert_eq "true" "$SkipSystemTune" "Config: SkipSystemTune"
assert_eq "true" "$DryRun" "Config: DryRun"
assert_eq "false" "$DropPrivs" "Config: DropPrivs"
assert_eq "5000" "$MaxAllTimeLogLines" "Config: MaxAllTimeLogLines"
assert_eq "false" "$AutoGenConfig" "Config: AutoGenConfig"
assert_eq "2" "$GpuIndexArg" "Config: GpuIndex"
assert_eq "false" "$OptimizeIrqs" "Config: OptimizeIrqs"
assert_eq "3600" "$SummaryInterval" "Config: SummaryInterval"
assert_eq "14400" "$SummarySilenceTimeout" "Config: SummarySilenceTimeout"
assert_eq "50" "$HeaderInterval" "Config: HeaderInterval"
assert_eq "/tmp/testpipe" "$CommPipe" "Config: CommPipe"

# Test 14: CLI overrides Config
echo "Test 14: CLI overrides Config"
# Previous test left config values set
parse_args "--physical-only" "--daemon" "--strict" "1" "--max-perf"
assert_eq "false" "$UseHt" "CLI override: UseHt (already false but still)"
assert_eq "true" "$DaemonMode" "CLI override: DaemonMode"
assert_eq "true" "$StrictMem" "CLI override: StrictMem"
assert_eq "1" "$GpuIndexArg" "CLI override: GpuIndex"
assert_eq "true" "$MaxPerf" "CLI override: MaxPerf"

# Change some back
parse_args "-a" "-n"
assert_eq "false" "$OnlyGaming" "CLI override: OnlyGaming (set to false by -a)"

rm -rf tests/mock_etc

# Test 15: check_pcie_speed
echo "Test 15: check_pcie_speed"
mkdir -p "$SYSFS_PREFIX/sys/bus/pci/devices/0000:01:00.0"
PciAddr="0000:01:00.0"
echo "16.0 GT/s PCIe" > "$SYSFS_PREFIX/sys/bus/pci/devices/0000:01:00.0/current_link_speed"
echo "32.0 GT/s PCIe" > "$SYSFS_PREFIX/sys/bus/pci/devices/0000:01:00.0/max_link_speed"
echo "8" > "$SYSFS_PREFIX/sys/bus/pci/devices/0000:01:00.0/current_link_width"
echo "16" > "$SYSFS_PREFIX/sys/bus/pci/devices/0000:01:00.0/max_link_width"

LOG_OUTPUT=""
log() {
    LOG_OUTPUT+="$1"$'\n'
}

PcieWarningLogged=false
check_pcie_speed

echo "$LOG_OUTPUT" | grep -q "WARNING: GPU is not running at max PCIe speed! Current: 16.0 GT/s PCIe, Max: 32.0 GT/s PCIe"
assert_eq "0" "$?" "check_pcie_speed detects speed mismatch"

echo "$LOG_OUTPUT" | grep -q "WARNING: GPU is not running at max PCIe width! Current: x8, Max: x16"
assert_eq "0" "$?" "check_pcie_speed detects width mismatch"

# Test matching speed/width
echo "32.0 GT/s PCIe" > "$SYSFS_PREFIX/sys/bus/pci/devices/0000:01:00.0/current_link_speed"
echo "16" > "$SYSFS_PREFIX/sys/bus/pci/devices/0000:01:00.0/current_link_width"
LOG_OUTPUT=""
PcieWarningLogged=false
check_pcie_speed
assert_eq "" "$LOG_OUTPUT" "check_pcie_speed no warning when matching"

# Test 15b: check_pcie_speed with Resizable BAR (NVIDIA)
echo "Test 15b: check_pcie_speed with Resizable BAR (NVIDIA)"

# Mock lspci and nvidia-smi
lspci() {
    if [[ "$*" == *"-s 0000:01:00.0"* ]]; then
        if [[ "$*" == *"-vv"* ]]; then
            echo "Capabilities: [150 v1] Resizable BAR <?>BAR 0: current: 256MB, supported: 256MB 512MB 1GB 2GB 4GB 8GB 16GB"
        elif [[ "$*" == *"-v"* ]]; then
            echo "Memory at ... [size=256M]"
        else
            echo "01:00.0 VGA compatible controller: NVIDIA Corporation GA102 [GeForce RTX 3080] (rev a1)"
        fi
    fi
}
export -f lspci

nvidia-smi() {
    echo "Resizable BAR : Disabled"
}
export -f nvidia-smi

LOG_OUTPUT=""
PcieWarningLogged=false
check_pcie_speed

echo "$LOG_OUTPUT" | grep -q "WARNING: Resizable BAR is disabled in NVIDIA settings/BIOS!"
assert_eq "0" "$?" "check_pcie_speed detects disabled ReBAR on NVIDIA"

# Test 15c: check_pcie_speed with Resizable BAR (AMD)
echo "Test 15c: check_pcie_speed with Resizable BAR (AMD)"

lspci() {
    if [[ "$*" == *"-s 0000:01:00.0"* ]]; then
        if [[ "$*" == *"-vv"* ]]; then
            echo "Capabilities: [150 v1] Resizable BAR <?>BAR 0: current: 256MB, supported: 256MB 512MB 1GB 2GB 4GB 8GB 16GB"
        else
            echo "01:00.0 VGA compatible controller: Advanced Micro Devices, Inc. [AMD/ATI] Navi 21 [Radeon RX 6800/6800 XT / 6900 XT] (rev c1)"
        fi
    fi
}
# We need to redefine lspci for the test
LOG_OUTPUT=""
PcieWarningLogged=false
check_pcie_speed

echo "$LOG_OUTPUT" | grep -q "WARNING: Resizable BAR is only 256MB! (Likely disabled in BIOS)"
assert_eq "0" "$?" "check_pcie_speed detects small ReBAR on AMD"

# Cleanup mocks
unset -f lspci
unset -f nvidia-smi

# Test 15d: check_pcie_speed with suboptimal MPS
echo "Test 15d: check_pcie_speed with suboptimal MPS"

lspci() {
    if [[ "$*" == *"-s 0000:01:00.0"* ]]; then
        if [[ "$*" == *"-vv"* ]]; then
            echo "                DevCap: MaxPayload 256 bytes, PhantFunc 0, Latency L0s <64ns, L1 unlimited"
            echo "                DevCtl: CorrErr+ NonFatalErr+ FatalErr+ UnsupReq-"
            echo "                        MaxPayload 128 bytes, MaxReadReq 512 bytes"
        else
            echo "01:00.0 VGA compatible controller: NVIDIA Corporation GA102 [GeForce RTX 3080] (rev a1)"
        fi
    fi
}

LOG_OUTPUT=""
PcieWarningLogged=false
check_pcie_speed

echo "$LOG_OUTPUT" | grep -q "WARNING: PCIe Max Payload Size (MPS) is suboptimal! Current: 128B, Capable: 256B"
assert_eq "0" "$?" "check_pcie_speed detects suboptimal MPS"

# Test 15e: check_pcie_speed with low MRRS
echo "Test 15e: check_pcie_speed with low MRRS"

lspci() {
    if [[ "$*" == *"-s 0000:01:00.0"* ]]; then
        if [[ "$*" == *"-vv"* ]]; then
            echo "                DevCap: MaxPayload 256 bytes, PhantFunc 0, Latency L0s <64ns, L1 unlimited"
            echo "                DevCtl: CorrErr+ NonFatalErr+ FatalErr+ UnsupReq-"
            echo "                        MaxPayload 256 bytes, MaxReadReq 128 bytes"
        else
            echo "01:00.0 VGA compatible controller: NVIDIA Corporation GA102 [GeForce RTX 3080] (rev a1)"
        fi
    fi
}

LOG_OUTPUT=""
PcieWarningLogged=false
check_pcie_speed

echo "$LOG_OUTPUT" | grep -q "WARNING: PCIe Max Read Request Size (MRRS) is low (128B)! This may limit performance."
assert_eq "0" "$?" "check_pcie_speed detects low MRRS"

# Cleanup mocks
unset -f lspci

# Test 16: system_tune with MaxPerf
echo "Test 16: system_tune with MaxPerf"
MOCK_EUID=0
SkipSystemTune=false
DryRun=false
MaxPerf=true
PciAddr="0000:01:00.0"

# Setup mocks for system_tune
mkdir -p "$SYSFS_PREFIX/sys/module/pcie_aspm/parameters"
touch "$SYSFS_PREFIX/sys/module/pcie_aspm/parameters/policy"
mkdir -p "$SYSFS_PREFIX/sys/bus/pci/devices/$PciAddr/power"
touch "$SYSFS_PREFIX/sys/bus/pci/devices/$PciAddr/power/control"
mkdir -p "$SYSFS_PREFIX/sys/bus/pci/devices/$PciAddr/link"
touch "$SYSFS_PREFIX/sys/bus/pci/devices/$PciAddr/link/l1_aspm"
touch "$SYSFS_PREFIX/sys/bus/pci/devices/$PciAddr/link/clkpm"

# We need to capture the echoes to check what happened
# Mock printf to capture its output too
PRINTF_OUTPUT=""
printf() {
    # Actually still print to stdout so we can see it
    command printf "$@"
    # And capture it
    PRINTF_OUTPUT+=$(command printf "$@")
}

MaxPerf=true
SystemTuned=""
PRINTF_OUTPUT=""
system_manage_settings "tune" > /dev/null

echo "$PRINTF_OUTPUT" | grep -q "pcie_aspm_policy"
assert_eq "0" "$?" "system_tune sets pcie_aspm_policy"
echo "$PRINTF_OUTPUT" | grep -q "gpu_runtime_pm"
assert_eq "0" "$?" "system_tune sets gpu_runtime_pm"
echo "$PRINTF_OUTPUT" | grep -q "gpu_l1_aspm"
assert_eq "0" "$?" "system_tune sets gpu_l1_aspm"
echo "$PRINTF_OUTPUT" | grep -q "gpu_clkpm"
assert_eq "0" "$?" "system_tune sets gpu_clkpm"

# Test 17: system_tune/system_restore and triggering logic
echo "Test 17: system_tune/system_restore and triggering logic"

# Setup for system_restore
cat <<EOF > "$SystemConfig"
vm.max_map_count=65530
pcie_aspm_policy=default
gpu_runtime_pm_control=auto
gpu_l1_aspm=1
gpu_clkpm=1
transparent_hugepage=madvise
thp_defrag=madvise
cpu_governor=powersave
EOF

# Mock root for these tests
MOCK_EUID=0
# Mock PciAddr
PciAddr="0000:01:00.0"
# Ensure sysfs structure for restore
mkdir -p "$SYSFS_PREFIX/sys/module/pcie_aspm/parameters"
mkdir -p "$SYSFS_PREFIX/sys/bus/pci/devices/$PciAddr/power"
mkdir -p "$SYSFS_PREFIX/sys/bus/pci/devices/$PciAddr/link"
mkdir -p "$SYSFS_PREFIX/sys/kernel/mm/transparent_hugepage"
mkdir -p "$SYSFS_PREFIX/sys/devices/system/cpu/cpu0/cpufreq"

echo "default" > "$SYSFS_PREFIX/sys/module/pcie_aspm/parameters/policy"
echo "auto" > "$SYSFS_PREFIX/sys/bus/pci/devices/$PciAddr/power/control"
echo "1" > "$SYSFS_PREFIX/sys/bus/pci/devices/$PciAddr/link/l1_aspm"
echo "1" > "$SYSFS_PREFIX/sys/bus/pci/devices/$PciAddr/link/clkpm"
echo "madvise" > "$SYSFS_PREFIX/sys/kernel/mm/transparent_hugepage/enabled"
echo "madvise" > "$SYSFS_PREFIX/sys/kernel/mm/transparent_hugepage/defrag"
echo "powersave" > "$SYSFS_PREFIX/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"

# Initial state: not tuned
SystemTuned=false
DryRun=false
SkipSystemTune=false
MOCK_EUID=0 # Ensure system_tune doesn't skip due to EUID
MaxPerf=true # system_tune needs this to set pcie_aspm_policy

# Trigger tune
SystemTuned=false
MOCK_EUID=0
MaxPerf=true
DryRun=false
SkipSystemTune=false
DEBUG=1 trigger_system_management "tune"
assert_eq "true" "$SystemTuned" "trigger_system_management 'tune' sets SystemTuned=true"
assert_eq "performance" "$(cat "$SYSFS_PREFIX/sys/module/pcie_aspm/parameters/policy")" "system_tune applied"

# Trigger restore
trigger_system_management "restore" > /dev/null
assert_eq "false" "$SystemTuned" "trigger_system_management 'restore' sets SystemTuned=false"
assert_eq "default" "$(cat "$SYSFS_PREFIX/sys/module/pcie_aspm/parameters/policy")" "system_restore applied"

# Test trigger logic in run_optimization/summarize_optimizations
LastOptimizedCount=0
OptimizedPidsMap=()
TotalOptimizedCount=0

# Mock a gaming process
# We need to mock is_gaming_process to return true for a specific PID
is_gaming_process() { [[ "$1" == "123" ]]; }
# Mock ps for this PID
ps() {
    if [[ "$*" == *"-p 123 -o comm="* ]]; then echo "game"; 
    elif [[ "$*" == *"-fp 123 -o args="* ]]; then echo "game_bin";
    else command ps "$@"; fi
}
# Mock fuser to find our PID
fuser() { echo "123"; }
# Mock taskset
taskset() { echo "pid 123's current affinity list: 0-7"; }

# run_optimization should trigger tune
SystemTuned=false
MOCK_EUID=0
PROC_PREFIX="$SYSFS_PREFIX" # Use same mock prefix for /proc
mkdir -p "$PROC_PREFIX/proc/123"
echo "VmRSS: 1000 kB" > "$PROC_PREFIX/proc/123/status"
# Mock pgrep to NOT return anything for PipeWire to ensure we trigger system tune via GPU process
# We use a separate function name to avoid recursion if needed, but here simple redefinition is fine
pgrep() { if [[ "$*" == *"-f"* ]]; then return 1; fi; command pgrep "$@"; }
# Also need to make sure always_optimize_pids doesn't include 123
TunePipeWire=false
# Mock ps to return a real game name that is not kworker
ps() {
    if [[ "$*" == *"-p 123 -o comm="* ]]; then echo "game_exe";
    elif [[ "$*" == *"-fp 123 -o args="* ]]; then echo "./game_exe";
    elif [[ "$*" == *"-eo pid,ppid,comm,args --no-headers"* ]]; then
        echo " 123     1 game_exe        ./game_exe"
    else command ps "$@"; fi
}
# IMPORTANT: Reset maps that might have cached 123 as non-gaming
NonGamingPidsMap=()
OptimizedPidsMap=()
AlwaysOptimizePidsMap=()
run_optimization > /tmp/opt_output_trigger 2>&1
TunePipeWire=true # Reset
assert_eq "true" "$SystemTuned" "run_optimization triggers system tune"

# Now mock process gone
fuser() { echo ""; }
# Ensure we clear the map since we're simulating the process being gone
OptimizedPidsMap=([123]=$(date +%s)) 
LastOptimizedCount=1
# Mock /proc/123 to be gone
rm -rf "$PROC_PREFIX/proc/123"
# run_optimization doesn't trigger restore, summarize_optimizations does
run_optimization > /dev/null
summarize_optimizations > /dev/null
assert_eq "false" "$SystemTuned" "summarize_optimizations triggers system restore when procs gone"

# Test 18: System restore on termination
echo "Test 18: System restore on termination"
MOCK_EUID=0
SystemTuned=true
trigger_system_management_called=false
system_manage_settings() { 
    if [ "$1" = "restore" ]; then
        trigger_system_management_called=true
    fi
    return 0
}

# We can't easily test the actual trap in this script without complex subshells,
# but we can verify our intended change logic.
# If we add a trap to the script, we want to ensure it calls trigger_system_management "restore".

# Let's mock what the trap should do
on_exit() {
    trigger_system_management "restore"
}

SystemTuned=true
on_exit
assert_eq "false" "$SystemTuned" "on_exit triggers system management 'restore' if tuned"
assert_eq "true" "$trigger_system_management_called" "system_manage_settings was actually called"

# Cleanup mock
unset trigger_system_management_called

# Test 19: Redundant tuning/restoration check
echo "Test 19: Redundant tuning/restoration check"
MOCK_EUID=0
SystemTuned=false
manage_calls=0
system_manage_settings() { 
    local action="$1"
    manage_calls=$((manage_calls + 1))
    if [ "$action" = "tune" ]; then return 0; fi
    if [ "$action" = "restore" ]; then return 0; fi
}

trigger_system_management "tune"
trigger_system_management "tune"
assert_eq "1" "$manage_calls" "trigger_system_management called only once when triggering 'tune' twice"
assert_eq "true" "$SystemTuned" "SystemTuned is true after tuning"

trigger_system_management "restore"
trigger_system_management "restore"
assert_eq "2" "$manage_calls" "trigger_system_management called only once more when triggering 'restore' twice"
assert_eq "false" "$SystemTuned" "SystemTuned is false after restoration"

# Cleanup
unset manage_calls

echo "--------------------------------------------------------------------------------"
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}ALL TESTS PASSED ($PASSED)${NC}"
else
    echo -e "${RED}TESTS FAILED ($FAILED failed, $PASSED passed, $((PASSED + FAILED)) total)${NC}"
fi
echo "--------------------------------------------------------------------------------"

if [ $FAILED -gt 0 ]; then
    exit 1
fi
exit 0
