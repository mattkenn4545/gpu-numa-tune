# 🚀 GPU NUMA Optimizer

**Unlock the full potential of your high-end gaming rig.** 

In multi-node systems (like AMD Threadripper, EPYC, or multi-socket Intel setups), the distance between your CPU and GPU matters—a lot. If your game is running on CPU cores that are "far" from your GPU, you're bleeding performance through increased latency and interconnect bottlenecks.

**GPU NUMA Optimizer** is a smart, cross-vendor daemon that dynamically binds your games to the exact CPU cores and memory nodes physically closest to your GPU. Stop leaving frames on the table and start gaming with surgical precision.

---

## ✨ Features

- **🎯 Precision Pinning:** Automatically detects your GPU's physical NUMA node and pins game threads to the most efficient CPU cores.
- **🧠 Intelligent Memory Migration:** Moves existing game memory allocations to the GPU's local NUMA node in real-time.
- **🕹️ Gaming-Aware Heuristics:** Automatically identifies games from Steam, Proton, Wine, Lutris, and Heroic by inspecting environment variables and process ancestry, while ignoring background apps like browsers or Discord.
- **⚡ System-Level Tuning:** Optimizes kernel parameters (`sysctl`), CPU governors, PCIe power management, and Transparent Hugepages (THP) for reduced scheduling latency and improved memory mapping.
- **🏎️ Max Performance Mode:** Optional high-performance mode that forces the GPU and PCIe bus to stay in their highest power states, preventing micro-stutter from power-saving transitions.
- **🩺 PCIe Health Check:** Monitors and warns if the GPU is not running at its maximum supported PCIe generation or link width (e.g., running at x8 instead of x16).
- **🛡️ Cross-Vendor Support:** Seamlessly works with NVIDIA, AMD, and Intel GPUs.
- **🔄 Smart Daemon Mode:** Silently monitors your system every 10 seconds, optimizing new games as they launch and providing status summaries every 30 minutes. Summaries are automatically silenced after 2 hours of inactivity to keep your logs clean, and will resume once a qualifying process is detected.
- **🔔 Smart Notifications:** Aggregates multiple process optimizations (like when a game launches with several helper processes) into a single, clean notification to avoid spam.
- **⚖️ Priority Management:** Gives games higher CPU (`renice`) and IO (`ionice`) priority to ensure they aren't throttled by background tasks.
- **🧬 Nearby Node Support:** If the local node is full, it intelligently expands to the next closest nodes based on hardware distance.
- **⚙️ Per-Process Configuration:** Fine-tune settings like HT usage, memory locality, or process priority for specific games using dedicated `.conf` files (e.g., `Cyberpunk2077.exe.conf`).
- **📈 All-Time Tracking:** Maintains a persistent log of every optimization across reboots, providing historical insights into your system's performance tuning.
- **📊 Real-time Monitoring:** Periodically summarizes active optimizations and cleans up dead processes from tracking, with automatic silencing during periods of inactivity.
- **🛠️ Auto-Config Generation:** Automatically creates template configuration files for detected games, making it easy to customize per-process settings like priority and affinity.

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

### 3. Configuration

The optimizer can be configured via persistent configuration files. Settings are loaded in the following order (later files override earlier ones):

1.  `/etc/gpu-numa-tune.conf` (System-wide)
2.  `~/.config/gpu-numa-tune.conf` (User-specific)
3.  `./gpu-numa-tune.conf` (Local directory)

#### Per-Process Configuration:
You can also create process-specific configuration files. The optimizer looks for files named `<executable_name>.conf` (e.g., `Cyberpunk2077.exe.conf`) in:

1.  `/etc/gpu-numa-tune/`
2.  `~/.config/gpu-numa-tune/`
3.  The current working directory of the script.

These per-process configs can override settings like `UseHt`, `IncludeNearby`, `MaxDist`, `StrictMem`, `ReniceValue`, and `IoniceValue` for that specific game without affecting global behavior.

When a new process is optimized, the script automatically creates a template configuration file in your user config directory (if `AutoGenConfig=true`), populated with the current global defaults.

**Note:** Command-line options always take precedence over configuration file values.

#### Format:
The configuration file uses a simple `KEY=VALUE` format. Lines starting with `#` are ignored as comments.

```ini
# Example configuration
UseHt=true
DaemonMode=true
SleepInterval=10
GpuIndex=0
```

#### Available Options:

| Key | Description | Default |
| :--- | :--- | :--- |
| `UseHt` | Use SMT/HT sibling cores (`true`/`false`) | `true` |
| `DaemonMode` | Run in daemon mode (`true`/`false`) | `false` |
| `SleepInterval` | Seconds to wait between checks in daemon mode | `10` |
| `StrictMem` | Use `membind` (fails if node full) instead of `preferred` | `false` |
| `IncludeNearby` | Include "nearby" NUMA nodes based on distance | `true` |
| `MaxDist` | Max distance from `numactl -H` for "nearby" nodes | `11` |
| `OnlyGaming` | Only optimize games and high-perf apps | `true` |
| `MaxPerf` | Force max PCIe performance (disable ASPM/Runtime PM) | `true` |
| `ReniceValue` | Nice value for optimized processes (-20 to 19, "" to skip) | `-10` |
| `IoniceValue` | Ionice class/value (e.g., "best-effort:0", "" to skip) | `best-effort:0` |
| `SkipSystemTune` | Skip modifying `sysctl` or CPU governors | `false` |
| `DryRun` | Log intended changes without applying them | `false` |
| `DropPrivs` | Drop root privileges after system tuning | `true` |
| `AutoGenConfig` | Create per-command default configuration files | `true` |
| `MaxAllTimeLogLines` | Max lines to keep in `~/.gpu_numa_optimizations` | `10000` |
| `OptimizeIrqs` | Pin GPU interrupts to local NUMA node (`true`/`false`) | `true` |
| `GpuIndex` | Default GPU index to target | `0` |
| `SummaryInterval` | Interval between periodic summary reports (seconds) | `1800` |
| `SummarySilenceTimeout` | Stop summaries after inactivity (seconds) | `7200` |
| `HeaderInterval` | Number of log lines before repeating table header | `20` |

### 4. Command-Line Usage

While the configuration file is recommended for persistent settings, you can override any setting via command-line arguments.

**Usage:**
`sudo ./gpu_optimize.sh [options] [gpu_index]`

** Options:**
- `-p, --physical-only`: Skip SMT/Hyper-threading siblings (sets `UseHt=false`).
- `-d, --daemon`: Run in daemon mode (sets `DaemonMode=true`).
- `-s, --strict`: Strict memory policy (sets `StrictMem=true`).
- `-l, --local-only`: Use only local node (sets `IncludeNearby=false`).
- `-a, --all-gpu-procs`: Optimize all GPU processes (sets `OnlyGaming=false`).
- `-f, --max-perf`: Force maximum PCIe performance (sets `MaxPerf=true`).
- `--no-irq`: Skip pinning GPU interrupts to the local NUMA node (sets `OptimizeIrqs=false`).
- `-x, --no-tune`: Skip system-level kernel tuning (sets `SkipSystemTune=true`).
- `-n, --dry-run`: Dry-run mode (sets `DryRun=true`).
- `-m, --max-log-lines`: Set max log lines (sets `MaxAllTimeLogLines`).
- `-c, --no-config`: Disable automatic configuration file generation (sets `AutoGenConfig=false`).
- `-k, --no-drop`: Do not drop root privileges (sets `DropPrivs=false`).
- `-h, --help`: Show full usage information.

**To edit the service settings:**
1. Run `sudo systemctl edit --full gpu-numa-optimizer.service`
2. Update the `ExecStart` line (e.g., `ExecStart=/usr/local/bin/gpu_optimize.sh -d -p`)
3. Save and exit. The service will restart automatically.

---

## 🧪 Testing

The project includes a test suite that mocks the system environment to verify the optimization logic.

### Running Tests
```bash
./tests/run_tests.sh
```

The tests cover argument parsing, CPU affinity normalization, process heuristics, and hardware resource discovery logic.

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
    - Filters out common non-gaming applications (browsers, Discord, etc.) and background services.

### 3. Execution, Memory & Priority Optimization
Once a game is identified, the script applies several distinct optimizations:
- **CPU Pinning (`taskset`)**: Forces the game threads to run *only* on the CPU cores physically wired to the GPU's PCI-E lanes. This eliminates "hop" latency across the Infinity Fabric or QPI/UPI.
- **Memory Policy (`numactl`)**: Sets the process's memory allocation policy to `preferred` (or `strict` with `--strict`) for the target NUMA nodes.
- **Live Migration (`migratepages`)**: Moves existing memory pages from "slow" remote nodes to the "fast" local node in real-time without restarting the game.
- **CPU Priority (`renice`)**: Boosts the process's scheduling priority (default nice value: `-10`) to ensure it gets preferential treatment by the kernel scheduler.
- **IO Priority (`ionice`)**: Sets the process's IO scheduling class and priority (default: `best-effort:0`) to reduce disk latency and prevent background tasks from stalling game assets loading.

### 4. Privilege Management & Security
To ensure maximum performance while maintaining security, the script handles privileges intelligently:
- **Kernel Tuning**: System-level optimizations (sysctl, CPU governor) require root and are performed once at startup.
- **Privilege Dropping (`setpriv`)**: After performing root-only tasks, the daemon automatically drops its privileges to the user currently running the X11/Wayland session. This allows it to send desktop notifications and interact with user processes safely.
- **Manual Control**: Use `--no-drop` if you need to keep root privileges for specific debugging scenarios.

### 5. Kernel Latency Tuning
If run as root, the script applies several system-level tweaks to reduce micro-stutter and ensure consistent performance:
- **`kernel.numa_balancing=0`**: Disables the kernel's automatic NUMA balancer, which can cause unpredictable "stutters" when it moves memory behind the game's back. We handle placement manually for maximum consistency.
- **`kernel.split_lock_mitigate=0`**: Disables split lock mitigation to prevent execution stalls in certain applications.
- **`vm.max_map_count`**: Increased to `2147483647` (max) to handle the heavy memory mapping requirements of modern AAA titles (like Star Citizen) and Wine/Proton.
- **`kernel.sched_migration_cost_ns`**: Tuned to `5000000` (5ms) to reduce unnecessary task migrations between cores.
- **`net.core.netdev_max_backlog`**: Increased network receive queue to `5000` to prevent packet drops during heavy load.
- **`net.core.busy_read/poll`**: Set to `50` for low-latency network polling for smoother online play.
- **`vm.stat_interval=10`**: Reduces background jitter by decreasing the frequency of virtual memory statistics collection.
- **`kernel.nmi_watchdog=0`**: Disables the NMI watchdog to reduce periodic interrupts and improve latency consistency.
- **Transparent Hugepages (THP)**: Set to `never` to prevent micro-stutters and stalls during dynamic allocation and defragmentation.
- **CPU Scaling Governor**: Automatically sets all cores to `performance` mode to prevent downclocking during gameplay.
- **IRQ Optimization**: Automatically pins GPU-associated interrupts to the local NUMA node's cores to minimize cross-node latency.
- **PCIe Max Performance**: If enabled, sets the global PCIe ASPM policy to `performance` and disables Runtime Power Management and ASPM for the target GPU.

### 6. PCIe Health Monitoring
When at least one process is optimized, the script periodically verifies the GPU's PCIe connection:
- **Generation Check**: Compares `current_link_speed` with `max_link_speed` from sysfs.
- **Width Check**: Compares `current_link_width` with `max_link_width` from sysfs.
- **Warnings**: If a mismatch is detected (e.g., a PCIe 4.0 card running at 3.0 speeds), a `WARNING` is logged to help the user identify potential hardware or BIOS configuration issues.

### 7. Smart Notification Aggregation
To prevent notification spam during complex game launches (e.g., Wine/Proton games starting `wineserver`, `explorer.exe`, and the game itself), the script implements a buffering system:
- **Delayed Delivery**: When a new optimization is detected, the daemon waits `SleepInterval + 5` seconds to catch any subsequent processes.
- **Amalgamated Messaging**: All processes optimized within that window are grouped into a single notification.
- **Primary Process Highlighting**: The process with the largest memory footprint (RSS) is automatically identified as the primary process and highlighted in the notification. This ensures the actual game is prioritized over helper processes like `wineserver`.
- **Warning Propagation**: If any single process in a batch fails migration or encounters full nodes, the entire notification is upgraded to a warning icon.
- **Automatic Summary & Silencing**: In daemon mode, a periodic summary of all active optimizations and total session stats is logged to the system journal every 30 minutes. This process also cleans up any tracked processes that are no longer running. To avoid cluttering logs during long periods of inactivity, these summaries are automatically silenced after 2 hours if no new processes are optimized. They resume immediately once a qualifying process is detected.

### 8. Persistent Tracking & Log Management
To provide a long-term view of your system's performance tuning, the script maintains a persistent log file:
- **`~/.gpu_numa_optimizations`**: A human-readable log file stored in the home directory of the user running the session. Each line records a unique optimization event with a timestamp, PID, process name, status, and target nodes.
- **Atomic Log Trimming**: To prevent the log from growing indefinitely, it is automatically trimmed when it exceeds the configured limit (default: 10,000 lines). The script uses a 50-line buffer and atomic file operations to ensure log integrity while minimizing disk I/O.
- **Global Stats**: The periodic status summary includes an "all-time" counter derived from this log, giving you a quick glance at how many processes have been optimized across all sessions.

### 9. Automatic System Tuning & Persistence
GPU NUMA Optimizer manages system-level kernel parameters dynamically to ensure high performance when needed and system stability when idle.

- **On-Demand Activation**: System-level optimizations (like `kernel.numa_balancing=0` and CPU governor changes) are applied the moment the first qualifying process is identified for optimization.
- **Original Value Persistence**: When the script first tunes a system setting, it reads the current kernel value and appends it to `/etc/gpu-numa-tune.conf`. This ensures that the original system state is "remembered" across reboots and service restarts.
- **Automatic Restoration**: When the last optimized process exits, or when the `gpu-numa-optimizer` service is stopped, the script automatically reverts all modified kernel parameters to their original values stored in the configuration file.
- **Manual Override**: If you wish to skip system-level tuning entirely, use the `--no-tune` flag or set `SkipSystemTune=true` in your configuration.

---

## 🤝 Collaborate with Me!

This project is built by and for the Linux gaming community. Whether you're a performance enthusiast, a kernel geek, or just someone who wants their games to run smoother, your input is welcome!

- **Found a bug?** Open an issue.
- **Have an idea?** Start a discussion or submit a PR.
- **Support more games?** Help us refine our heuristics.

Let's make Linux the ultimate platform for high-performance gaming together. 🐧🎮
