#!/bin/bash

# Clean up function
cleanup() {
    rm -rf tests/mock_bin tests/mock_proc tests/mock_sys
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
lspci() {
    echo "0000:01:00.0 VGA compatible controller: NVIDIA Corporation GA102 [GeForce RTX 3080] (rev a1)"
    echo "0000:41:00.0 VGA compatible controller: NVIDIA Corporation GA102 [GeForce RTX 3080] (rev a1)"
}

GpuIndexArg=1
detect_gpu
assert_eq "0000:41:00.0" "$PciAddr" "detect_gpu index 1"

echo -e "\nSummary: ${GREEN}$PASSED passed${NC}, ${RED}$FAILED failed${NC}"
if [ $FAILED -gt 0 ]; then
    exit 1
fi
exit 0
