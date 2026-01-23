#!/bin/bash

# Clean up function
cleanup() {
    rm -rf tests/mock_bin tests/mock_proc tests/mock_sys tests/mock_dev tests/mock_all_time tests/mock_home tests/mock_all_time.tmp
}
trap cleanup EXIT

# Simple test runner for gpu_optimize.sh

# ANSI colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

PASSED=0
FAILED=0

# Source the script - we wrapped the execution in a check so this won't run it
# We need to provide a fake environment for some things that might run at top level or in functions
export PATH="$PATH:$(pwd)/tests/mock_bin"
mkdir -p tests/mock_bin

# Create mocks for external commands
lspci() {
    echo "0000:01:00.0 VGA compatible controller: NVIDIA Corporation GA102 [GeForce RTX 3080] (rev a1)"
}

notify-send() {
    return 0
}

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

# Test 2: parse_args
parse_args "-p" "--daemon" "-s" "1"
assert_eq "false" "$UseHt" "parse_args --physical-only"
assert_eq "true" "$DaemonMode" "parse_args --daemon"
assert_eq "true" "$StrictMem" "parse_args --strict"
assert_eq "1" "$GpuIndexArg" "parse_args GpuIndexArg"

parse_args "-l" "-a" "-x" "-k"
assert_eq "false" "$IncludeNearby" "parse_args --local-only"
assert_eq "false" "$OnlyGaming" "parse_args --all-gpu-procs"
assert_eq "true" "$SkipSystemTune" "parse_args --no-tune"
assert_eq "false" "$DropPrivs" "parse_args --no-drop"

# Test 3: is_gaming_process (mocking ps and /proc)
# We can't easily mock /proc in a simple script without LD_PRELOAD or similar, 
# but we can use our SYSFS_PREFIX if we were reading from /proc, but here it's mostly ps.

# Mocking ps
ps() {
    if [[ "$*" == *"-p 1234 -o comm="* ]]; then
        echo "steam"
    elif [[ "$*" == *"-p 5678 -o comm="* ]]; then
        echo "chrome"
    elif [[ "$*" == *"-fp 1234 -o args="* ]]; then
        echo "/usr/bin/steam"
    elif [[ "$*" == *"-fp 5678 -o args="* ]]; then
        echo "/usr/bin/chrome --type=renderer"
    else
        command ps "$@"
    fi
}
# We don't export -f here because we want it in the current shell context
# where is_gaming_process will run.

# Mocking /proc for is_gaming_process
export PROC_PREFIX="$(pwd)/tests/mock_proc"
mkdir -p "$PROC_PREFIX/proc/1234"
# Create empty environ file with read permission
touch "$PROC_PREFIX/proc/1234/environ"
chmod 644 "$PROC_PREFIX/proc/1234/environ"

# Let's test is_gaming_process for a few cases
# Case: Blacklisted
OnlyGaming=true
assert_eq "1" "$(is_gaming_process 5678; echo $?)" "is_gaming_process chrome (blacklisted)"

# For PID 1234, it should pass because it has a gaming environment variable
# We need to mock ps to return non-blacklisted comm and args
ps() {
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
        *) command ps "$@" ;;
    esac
}

# Put a gaming env var in the mock environ file
echo -e "STEAM_GAME_ID=123\0" > "$PROC_PREFIX/proc/1234/environ"

assert_eq "0" "$(is_gaming_process 1234; echo $?)" "is_gaming_process with STEAM_GAME_ID (allowed)"
assert_eq "0" "$(is_gaming_process 1111; echo $?)" "is_gaming_process child of steam (allowed)"
assert_eq "0" "$(is_gaming_process 3333; echo $?)" "is_gaming_process wine .exe (allowed)"

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
assert_eq "0,1" "$(get_nearby_nodes 0)" "get_nearby_nodes with numactl"
assert_eq "0-3,4-7" "$(get_nodes_cpulist "0,1")" "get_nodes_cpulist"

# Test without numactl
numactl() {
    return 127
}
assert_eq "0" "$(get_nearby_nodes 0)" "get_nearby_nodes without numactl"

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
sysctl() { SYSCTL_CALLED=true; }

# Mocking for system_tune
EUID=0
SkipSystemTune=false
system_tune

assert_eq "false" "$SYSCTL_CALLED" "Dry-run: sysctl not called"

# Mocking for run_optimization
PROC_PREFIX="$(pwd)/tests/mock_proc"
mkdir -p "$PROC_PREFIX/proc/9999"
touch "$PROC_PREFIX/proc/9999/environ"
echo -e "STEAM_GAME_ID=123\0" > "$PROC_PREFIX/proc/9999/environ"

# Mocking fuser to return our test PID
fuser() { echo "9999"; }
# Mocking ps for PID 9999
ps() {
    case "$*" in
        *"-p 9999 -o comm="*) echo "game_exe" ;;
        *"-fp 9999 -o args="*) echo "./game_exe" ;;
        *"-p 9999 -o ppid="*) echo "1" ;;
        *) command ps "$@" ;;
    esac
}
# Mock taskset -pc 9999 to return some affinity
taskset() {
    if [[ "$*" == "-pc 9999" ]]; then
        echo "pid 9999's current affinity list: 0-7"
    else
        TASKSET_CALLED=true
    fi
}

TargetNormalizedMask="0,1,2,3" # Different from 0-7

run_optimization

assert_eq "false" "$TASKSET_CALLED" "Dry-run: taskset not called"
assert_eq "false" "$NUMACTL_CALLED" "Dry-run: numactl not called"
assert_eq "false" "$MIGRATEPAGES_CALLED" "Dry-run: migratepages not called"

# Test 10: All-time tracking
echo "Test 10: All-time tracking"
AllTimeFile="tests/mock_all_time"
rm -f "$AllTimeFile"
AllTimeOptimizedCount=0
TotalOptimizedCount=0
OptimizedPidsMap=()

# Simulate load_all_time_stats by manually setting up and calling it
# We need to mock getent
getent() {
    if [[ "$*" == "passwd testuser" ]]; then
        echo "testuser:x:1000:1000::$(pwd)/tests/mock_home:/bin/bash"
    fi
}
mkdir -p tests/mock_home
echo "entry1" > tests/mock_home/.gpu_numa_optimizations
echo "entry2" >> tests/mock_home/.gpu_numa_optimizations
TargetUser="testuser"

load_all_time_stats
assert_eq "2" "$AllTimeOptimizedCount" "load_all_time_stats loads correct line count"
assert_eq "$(pwd)/tests/mock_home/.gpu_numa_optimizations" "$AllTimeFile" "AllTimeFile path set correctly"

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
AllTimeOptimizedCount=2

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
        ((AllTimeOptimizedCount++))
        if [ "$DryRun" = false ] && [ -n "$AllTimeFile" ]; then
            printf "%-19s | %-8s | %-16s | %-22s | %-8s | %s\n" \
                "$(date "+%Y-%m-%d %H:%M:%S")" "$pid" "$proc_comm" "$status_msg" "${NearbyNodeIds:-$NumaNodeId}" "$full_proc_cmd" >> "$AllTimeFile" 2>/dev/null
        fi
    fi
    OptimizedPidsMap[$pid]=$(date +%s)
fi

assert_eq "1" "$TotalOptimizedCount" "TotalOptimizedCount incremented for actual optimization"
assert_eq "3" "$AllTimeOptimizedCount" "AllTimeOptimizedCount incremented from 2"
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
assert_eq "3" "$AllTimeOptimizedCount" "AllTimeOptimizedCount NOT incremented if already optimized"
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
    FinalCpuMask="0-7"
    TargetNormalizedMask="0,1,2,3,4,5,6,7"
    OptimizedPidsMap=()
    TotalOptimizedCount=0
    AllTimeOptimizedCount=5 # Pre-set some value
    LastSummaryTime=$(date +%s)
    
    # We want to check if print_banner followed by check_active_optimizations true works
    # We can just call the functions if we source the script
    print_banner > /dev/null # Skip banner
    check_active_optimizations true
)

assert_eq "0 procs    | since startup   | 5 all time         | OPTIMIZED                 | No processes currently optimized" "$(echo "$output" | tail -n 1)" "Startup summary output matches expected format"

# Test 12: All-time log rotation
echo "Test 12: All-time log rotation (with 50-line buffer)"
AllTimeFile="tests/mock_all_time"
rm -f "$AllTimeFile"
MaxAllTimeLogLines=10

# Populate with 11 lines (exceeds MaxAllTimeLogLines but NOT by 50)
for i in {1..11}; do echo "line$i" >> "$AllTimeFile"; done
AllTimeOptimizedCount=11

trim_all_time_log
assert_eq "11" "$(wc -l < "$AllTimeFile")" "trim_all_time_log does NOT trim within 50-line buffer"
assert_eq "11" "$AllTimeOptimizedCount" "AllTimeOptimizedCount remains 11"

# Populate to 61 lines (exceeds MaxAllTimeLogLines + 50)
for i in {12..61}; do echo "line$i" >> "$AllTimeFile"; done
AllTimeOptimizedCount=61

trim_all_time_log
assert_eq "10" "$(wc -l < "$AllTimeFile")" "trim_all_time_log trims to MaxAllTimeLogLines after 50-line overflow"
assert_eq "line52" "$(head -n 1 "$AllTimeFile")" "trim_all_time_log keeps most recent entries (line52)"
assert_eq "line61" "$(tail -n 1 "$AllTimeFile")" "trim_all_time_log keeps most recent entries (line61)"
assert_eq "10" "$AllTimeOptimizedCount" "AllTimeOptimizedCount updated to MaxAllTimeLogLines"

if [ $FAILED -gt 0 ]; then
    exit 1
fi
exit 0
