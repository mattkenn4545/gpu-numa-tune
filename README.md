# 🚀 GPU NUMA Optimizer

**Unlock the full potential of your high-end gaming rig.** 

In multi-node systems (like AMD Threadripper, EPYC, or multi-socket Intel setups), the distance between your CPU and GPU matters—a lot. If your game is running on CPU cores that are "far" from your GPU, you're bleeding performance through increased latency and interconnect bottlenecks.

**GPU NUMA Optimizer** is a smart, cross-vendor daemon that dynamically binds your games to the exact CPU cores and memory nodes physically closest to your GPU. Stop leaving frames on the table and start gaming with surgical precision.

---

## ✨ Features

- **🎯 Precision Pinning:** Automatically detects your GPU's physical NUMA node and pins game threads to the most efficient CPU cores.
- **🧠 Intelligent Memory Migration:** Moves existing game memory allocations to the GPU's local NUMA node in real-time.
- **🕹️ Gaming-Aware Heuristics:** Automatically identifies games from Steam, Proton, Wine, Lutris, and Heroic by inspecting environment variables and process ancestry, while ignoring background apps like browsers or Discord.
- **⚡ System-Level Tuning:** Optimizes kernel parameters (`sysctl`) for reduced scheduling latency and improved memory mapping.
- **🛡️ Cross-Vendor Support:** Seamlessly works with NVIDIA, AMD, and Intel GPUs.
- **🔄 Smart Daemon Mode:** Silently monitors your system, optimizing new games as they launch and providing periodic status summaries.
- **🔔 Smart Notifications:** Aggregates multiple process optimizations (like when a game launches with several helper processes) into a single, clean notification to avoid spam.
- **🧬 Nearby Node Support:** If the local node is full, it intelligently expands to the next closest nodes based on hardware distance.
- **📊 Real-time Monitoring:** Provides periodic status summaries of all optimized processes.

---

## 🚀 Quick Start

### 1. Prerequisites

Before installing, ensure you have the necessary tools. On most distributions, these can be installed via:

**Debian/Ubuntu:**
```bash
sudo apt update
sudo apt install pciutils psmisc util-linux numactl procps libnotify-bin
```

**Arch Linux:**
```bash
sudo pacman -S pciutils psmisc util-linux numactl procps-ng libnotify
```

**Fedora:**
```bash
sudo dnf install pciutils psmisc util-linux numactl procps-ng libnotify
```

### 2. Installation

Getting up and running takes seconds:

```bash
git clone https://github.com/mattkenn4545/gpu-numa-tune.git
cd gpu-numa-tune
sudo ./install.sh
```

The installer will copy the script to `/usr/local/bin`, set up a systemd service, and start it immediately.

### 3. Tweaking Settings

The optimizer is designed to work out-of-the-box, but you can customize its behavior by editing the systemd service file or running the script manually.

**Usage:**
`sudo ./gpu_optimize.sh [options] [gpu_index]`

**Common Options:**
- `-p, --physical-only`: Skip SMT/Hyper-threading siblings (often better for gaming).
- `-d, --daemon`: Run in daemon mode (periodically checks for new processes).
- `-s, --strict`: Force memory to stay on the local node (OOM risk if node is small, but maximum performance).
- `-l, --local-only`: Disable "nearby node" logic and stick strictly to the GPU's primary node.
- `-a, --all-gpu-procs`: Optimize *every* process using the GPU, not just games.
- `-x, --no-tune`: Skip system-level kernel tuning (sysctl, etc.).
- `-k, --no-drop`: Do not drop root privileges (useful for certain troubleshooting).
- `-h, --help`: Show full usage information.

**To edit the service settings:**
1. Run `sudo systemctl edit --full gpu-numa-optimizer.service`
2. Update the `ExecStart` line (e.g., `ExecStart=/usr/local/bin/gpu_optimize.sh -d -p`)
3. Save and exit. The service will restart automatically.

---

## 🛠️ Technical Details

GPU NUMA Optimizer performs several layers of low-level system optimization to ensure zero-bottleneck performance.

### 1. Hardware Discovery & Topology Mapping
The script begins by mapping the physical relationship between your GPU and CPU:
- **`lspci`**: Identifies the GPU's PCI address and vendor.
- **`sysfs` (`/sys/bus/pci/devices/...`)**: Directly queries the kernel for the GPU's "local" NUMA node and CPU core list.
- **`numactl --hardware`**: Calculates "Nearby Nodes" based on SLIT (System Locality Information Table) distance, allowing expansion to adjacent nodes if the primary node is saturated.

### 2. Intelligent Process Targeting
Unlike blind optimizers, this script uses surgical precision to find games:
- **`fuser`**: Scans `/dev/dri/renderD*` (AMD/Intel/Mesa) and `/dev/nvidia*` (NVIDIA) to find every PID currently holding a GPU handle.
- **Heuristic Engine**: 
    - Inspects `/proc/$pid/environ` for Steam, Proton, and Wine environment variables.
    - Uses `ps` to identify common game engines (Unity, Unreal) and launchers (Lutris, Heroic).
    - Checks process lineage to catch child processes spawned by game launchers.

### 3. Execution & Memory Optimization
Once a game is identified, the script applies three distinct optimizations:
- **CPU Pinning (`taskset`)**: Forces the game threads to run *only* on the CPU cores physically wired to the GPU's PCI-E lanes. This eliminates "hop" latency across the Infinity Fabric or QPI/UPI.
- **Memory Policy (`numactl`)**: Sets the process's memory allocation policy to `preferred` (or `strict` with `--strict`) for the target NUMA nodes.
- **Live Migration (`migratepages`)**: Moves existing memory pages from "slow" remote nodes to the "fast" local node in real-time without restarting the game.

### 4. Privilege Management & Security
To ensure maximum performance while maintaining security, the script handles privileges intelligently:
- **Kernel Tuning**: System-level optimizations (sysctl, CPU governor) require root and are performed once at startup.
- **Privilege Dropping (`setpriv`)**: After performing root-only tasks, the daemon automatically drops its privileges to the user currently running the X11/Wayland session. This allows it to send desktop notifications and interact with user processes safely.
- **Manual Control**: Use `--no-drop` if you need to keep root privileges for specific debugging scenarios.

### 5. Kernel Latency Tuning
If run as root, the script applies several system-level tweaks to reduce micro-stutter and ensure consistent performance:
- **`kernel.numa_balancing=0`**: Disables the kernel's automatic NUMA balancer, which can cause unpredictable "stutters" when it moves memory behind the game's back.
- **`kernel.split_lock_mitigate=0`**: Disables split lock mitigation to prevent execution stalls in certain applications.
- **`vm.max_map_count`**: Increased to `2147483647` to handle the heavy memory mapping requirements of modern AAA titles and Wine/Proton.
- **`kernel.sched_migration_cost_ns`**: Tuned to `5000000` (5ms) to reduce unnecessary task migrations between cores.
- **`net.core.netdev_max_backlog`**: Increased network receive queue to `5000` to prevent packet drops during heavy load.
- **`net.core.busy_read/poll`**: Set to `50` for low-latency network polling for smoother online play.
- **`vm.stat_interval=10`**: Reduces background jitter by decreasing the frequency of virtual memory statistics collection.
- **`kernel.nmi_watchdog=0`**: Disables the NMI watchdog to reduce periodic interrupts and improve latency consistency.
- **Transparent Hugepages (THP)**: Set to `never` to prevent micro-stutters and stalls during dynamic allocation and defragmentation.
- **CPU Scaling Governor**: Automatically sets all cores to `performance` mode to prevent downclocking during gameplay.

### 6. Smart Notification Aggregation
To prevent notification spam during complex game launches (e.g., Wine/Proton games starting `wineserver`, `explorer.exe`, and the game itself), the script implements a buffering system:
- **Delayed Delivery**: When a new optimization is detected, the daemon waits `SleepInterval + 5` seconds to catch any subsequent processes.
- **Amalgamated Messaging**: All processes optimized within that window are grouped into a single notification.
- **Primary Process Highlighting**: The process with the largest memory footprint (RSS) is automatically identified as the primary process and highlighted in the notification. This ensures the actual game is prioritized over helper processes like `wineserver`.
- **Warning Propagation**: If any single process in a batch fails migration or encounters full nodes, the entire notification is upgraded to a warning icon.

---

## 🤝 Collaborate with Me!

This project is built by and for the Linux gaming community. Whether you're a performance enthusiast, a kernel geek, or just someone who wants their games to run smoother, your input is welcome!

- **Found a bug?** Open an issue.
- **Have an idea?** Start a discussion or submit a PR.
- **Support more games?** Help us refine our heuristics.

Let's make Linux the ultimate platform for high-performance gaming together. 🐧🎮
