---
title: Proxmox VE Setup on Bare Metal Server
description: Proxmox VE (latest version 8.x) on a bare metal server — from hardware preparation, BIOS configuration, installation walkthrough, network setup, storage management, to creating your first virtual machines and containers.
navigation:
  icon: i-lucide-server-cog
  title: Proxmox Bare Metal Setup
---

## Introduction

**Proxmox Virtual Environment (VE)** is an open-source server virtualization platform built on Debian Linux. It combines **KVM hypervisor** for full virtualization and **LXC** for lightweight container-based virtualization — all managed through a powerful web-based interface. Proxmox is the go-to choice for homelabs, enterprise virtualization, and building pentesting lab infrastructure.

::note
This guide covers **Proxmox VE 8.x** (latest stable release) installed on a **bare metal server** — meaning Proxmox is installed directly on the physical hardware, not inside another VM.
::

```
┌─────────────────────────────────────────────────────────────────┐
│                   PROXMOX VE ARCHITECTURE                       │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                  Web Management Interface                 │  │
│  │                  https://IP:8006                          │  │
│  └───────────────────────────┬───────────────────────────────┘  │
│                              │                                  │
│  ┌───────────────────────────┴───────────────────────────────┐  │
│  │                    Proxmox VE Layer                        │  │
│  │         Cluster Management · API · Firewall               │  │
│  │         Backup · HA · Replication · Storage                │  │
│  └───────────────┬───────────────────────┬───────────────────┘  │
│                  │                       │                      │
│  ┌───────────────┴──────────┐ ┌──────────┴──────────────────┐  │
│  │     KVM / QEMU           │ │         LXC                  │  │
│  │   Full Virtualization    │ │   OS-Level Containers        │  │
│  │                          │ │                              │  │
│  │  ┌─────┐ ┌─────┐ ┌────┐ │ │  ┌─────┐ ┌─────┐ ┌──────┐  │  │
│  │  │ VM1 │ │ VM2 │ │VM3 │ │ │  │ CT1 │ │ CT2 │ │ CT3  │  │  │
│  │  │Win  │ │Linux│ │BSD │ │ │  │Nginx│ │MySQL│ │Docker│  │  │
│  │  └─────┘ └─────┘ └────┘ │ │  └─────┘ └─────┘ └──────┘  │  │
│  └──────────────────────────┘ └──────────────────────────────┘  │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              Debian Linux Base (Kernel 6.x)               │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              Bare Metal Hardware (Physical Server)        │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

::card-group
  ::card
  ---
  title: Proxmox VE Official Docs
  icon: i-lucide-book-open
  to: https://pve.proxmox.com/pve-docs/
  target: _blank
  ---
  Complete official Proxmox VE administration guide — the primary reference for all configurations.
  ::

  ::card
  ---
  title: Proxmox VE Wiki
  icon: i-lucide-book-marked
  to: https://pve.proxmox.com/wiki/Main_Page
  target: _blank
  ---
  Community-driven wiki with tutorials, troubleshooting, and best practices.
  ::

  ::card
  ---
  title: Proxmox VE Downloads
  icon: i-lucide-download
  to: https://www.proxmox.com/en/downloads
  target: _blank
  ---
  Download the latest Proxmox VE ISO installer and documentation.
  ::

  ::card
  ---
  title: Proxmox Forum
  icon: i-lucide-message-circle
  to: https://forum.proxmox.com/
  target: _blank
  ---
  Official community forum for support, discussions, and sharing configurations.
  ::
::

::badge
**Tags: tutorials · proxmox · bare-metal · virtualization · homelab · kvm · lxc · server-setup · hypervisor**
::

---

## Prerequisites & Hardware Requirements

### Minimum vs Recommended Hardware

::caution
Proxmox VE runs directly on hardware — insufficient specs will cause poor VM performance. Plan your hardware based on how many VMs/containers you intend to run.
::

| Component | Minimum | Recommended | Optimal (Lab/Production) |
| --- | --- | --- | --- |
| **CPU** | 64-bit (Intel EMT64 / AMD64) | Intel VT-x / AMD-V capable | Multi-core Xeon / EPYC with IOMMU |
| **RAM** | 2 GB (Proxmox only) | 16 GB | 64 GB+ (ECC recommended) |
| **Storage (OS)** | 32 GB SSD | 128 GB SSD | 256 GB NVMe SSD |
| **Storage (VMs)** | Any available | Separate SSD/NVMe | ZFS mirror/RAID, Ceph |
| **Network** | 1× 1Gbps NIC | 2× 1Gbps NIC (bonding) | 2× 10Gbps NIC |
| **BIOS** | UEFI recommended | UEFI with Secure Boot | UEFI + IPMI/iDRAC/iLO |

### Verify Hardware Virtualization Support

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---

```bash [Check Virtualization Support]
# ============================================
# BEFORE INSTALLING — Verify from any Linux live USB
# ============================================

# Check CPU virtualization support
egrep -c '(vmx|svm)' /proc/cpuinfo
# Output > 0 means virtualization is supported
# vmx = Intel VT-x
# svm = AMD-V

# Detailed CPU flags
lscpu | grep -i virtualization
# Output: Virtualization: VT-x  (or AMD-V)

# Check IOMMU support (needed for PCIe passthrough)
dmesg | grep -i iommu

# Check available RAM
free -h

# Check storage devices
lsblk
fdisk -l

# Check network interfaces
ip link show
```

#code
```bash
# Quick check
egrep -c '(vmx|svm)' /proc/cpuinfo
lscpu | grep -i virtualization
```
::

### What You'll Need

::field-group
  ::field{name="Proxmox VE ISO" type="required"}
  Download from [proxmox.com/downloads](https://www.proxmox.com/en/downloads) — latest stable 8.x release (~1.2 GB).
  ::

  ::field{name="USB Flash Drive" type="required"}
  Minimum 2 GB USB drive for the bootable installer. All data will be erased.
  ::

  ::field{name="Dedicated Server" type="required"}
  Physical server or workstation with virtualization-capable CPU. No other OS should be installed.
  ::

  ::field{name="Network Connection" type="required"}
  Ethernet connection with a static IP address or DHCP reservation for the Proxmox host.
  ::

  ::field{name="Monitor & Keyboard" type="temporary"}
  Needed only during installation. After setup, everything is managed via web interface.
  ::

  ::field{name="Another Computer" type="required"}
  To access the Proxmox web interface after installation (any machine on the same network).
  ::
::

---

## Phase 1 — Downloading Proxmox VE ISO

::steps{level="4"}

#### Step 1: Navigate to the Proxmox Download Page

Go to the official Proxmox VE download page and download the latest ISO installer.

::card
---
title: Download Proxmox VE 8.x ISO
icon: i-lucide-download
to: https://www.proxmox.com/en/downloads/proxmox-virtual-environment/iso
target: _blank
---
Always download from the official source to ensure integrity. Current latest: Proxmox VE 8.4.
::

![Proxmox Download Page](https://www.yourserveradmin.com/wp-content/uploads/2023/07/proxmox-download-page.png)

#### Step 2: Verify the ISO Integrity

```bash [Verify ISO Checksum]
# Download the SHA256 checksum file from the same download page
# Verify the downloaded ISO

# Linux/macOS
sha256sum proxmox-ve_8.4-1.iso

# Compare with the checksum listed on the download page
# They MUST match — if not, re-download

# Windows (PowerShell)
Get-FileHash .\proxmox-ve_8.4-1.iso -Algorithm SHA256
```

#### Step 3: Create a Bootable USB Drive

::tabs
  :::tabs-item{icon="i-simple-icons-linux" label="Linux (dd)"}
  ```bash [Create Bootable USB — Linux]
  # ============================================
  # FIND YOUR USB DEVICE
  # ============================================
  
  # List all block devices
  lsblk
  
  # Identify your USB drive (e.g., /dev/sdb)
  # WARNING: Make sure you select the correct device!
  # Using the wrong device will DESTROY data!
  
  # ============================================
  # WRITE ISO TO USB
  # ============================================
  
  # Unmount if auto-mounted
  sudo umount /dev/sdb*
  
  # Write ISO using dd
  sudo dd if=proxmox-ve_8.4-1.iso of=/dev/sdb bs=4M status=progress conv=fdatasync
  
  # Wait for completion — do NOT remove USB until done
  sync
  
  echo "[✓] Bootable USB created successfully"
  ```
  :::

  :::tabs-item{icon="i-simple-icons-windows" label="Windows (Rufus/Etcher)"}
  ```yaml [Create Bootable USB — Windows]
  # ============================================
  # OPTION 1: Rufus (Recommended)
  # ============================================
  # Download: https://rufus.ie/
  
  Steps:
    1. Insert USB drive
    2. Open Rufus
    3. Device: Select your USB drive
    4. Boot selection: Click SELECT → choose proxmox-ve_8.4-1.iso
    5. Partition scheme: GPT (for UEFI) or MBR (for Legacy BIOS)
    6. Target system: UEFI (non CSM) — recommended
    7. File system: FAT32 (default)
    8. Click START
    9. If prompted, select "Write in DD Image mode"
    10. Wait for completion
  
  # ============================================
  # OPTION 2: balenaEtcher
  # ============================================
  # Download: https://etcher.balena.io/
  
  Steps:
    1. Open Etcher
    2. Click "Flash from file" → select ISO
    3. Click "Select target" → select USB drive
    4. Click "Flash!"
    5. Wait for completion and verification
  ```
  :::

  :::tabs-item{icon="i-simple-icons-apple" label="macOS"}
  ```bash [Create Bootable USB — macOS]
  # Find USB device
  diskutil list
  
  # Identify your USB (e.g., /dev/disk4)
  # Unmount it
  diskutil unmountDisk /dev/disk4
  
  # Write ISO
  sudo dd if=proxmox-ve_8.4-1.iso of=/dev/rdisk4 bs=4m status=progress
  
  # Wait for completion
  sync
  
  # Eject
  diskutil eject /dev/disk4
  ```
  :::
::

::

---

## Phase 2 — BIOS/UEFI Configuration

::warning
Proper BIOS/UEFI configuration is **critical** for Proxmox performance and feature support. Incorrect settings can prevent booting, disable hardware virtualization, or cause performance issues.
::

### Enter BIOS/UEFI Setup

```
┌─────────────────────────────────────────────────┐
│          BIOS ACCESS KEYS BY MANUFACTURER        │
│                                                 │
│  Dell:          F2 or F12                       │
│  HP:            F10 or ESC                      │
│  Lenovo:        F1 or F2                        │
│  Supermicro:    DEL or F2                       │
│  ASRock:        F2 or DEL                       │
│  ASUS:          F2 or DEL                       │
│  Gigabyte:      F2 or DEL                       │
│  Intel NUC:     F2                              │
│  Generic:       DEL, F1, F2, F10, F12, ESC      │
└─────────────────────────────────────────────────┘
```

### Required BIOS Settings

::accordion
  :::accordion-item{icon="i-lucide-cpu" label="1. Enable Hardware Virtualization"}
  ```yaml [Virtualization Settings]
  # ============================================
  # LOCATION VARIES BY MANUFACTURER
  # ============================================
  
  # Intel Systems:
  #   Advanced → CPU Configuration → Intel Virtualization Technology → ENABLED
  #   Advanced → CPU Configuration → Intel VT-d → ENABLED
  
  # AMD Systems:
  #   Advanced → CPU Configuration → SVM Mode → ENABLED
  #   Advanced → CPU Configuration → IOMMU → ENABLED
  
  # ============================================
  # WHAT EACH SETTING DOES
  # ============================================
  
  Intel VT-x / AMD-V (SVM):
    Purpose: "Hardware-assisted CPU virtualization"
    Required: "YES — Proxmox will not work without this"
    Impact: "Allows VMs to run at near-native CPU speed"
  
  Intel VT-d / AMD IOMMU:
    Purpose: "Direct device assignment (PCIe passthrough)"
    Required: "Only if you want GPU/NIC passthrough"
    Impact: "Pass physical devices directly to VMs"
  
  Intel VT-x with EPT / AMD RVI:
    Purpose: "Hardware-assisted memory virtualization"
    Required: "Recommended — significantly improves VM performance"
    Impact: "Reduces memory management overhead"
  
  SR-IOV:
    Purpose: "Single Root I/O Virtualization"
    Required: "Only for network adapter sharing"
    Impact: "Share one physical NIC across multiple VMs"
  ```
  :::

  :::accordion-item{icon="i-lucide-hard-drive" label="2. Storage Controller Settings"}
  ```yaml [Storage Controller Configuration]
  # ============================================
  # SATA/AHCI CONFIGURATION
  # ============================================
  
  SATA Mode:
    Setting: "AHCI (NOT IDE or RAID*)"
    Location: "Advanced → SATA Configuration → SATA Mode"
    Note: "AHCI provides best performance for SSDs"
    Exception: "Use RAID mode only if using hardware RAID controller"
  
  # ============================================
  # NVMe CONFIGURATION
  # ============================================
  
  NVMe:
    Setting: "Ensure NVMe drives are detected in BIOS"
    Location: "Advanced → NVMe Configuration"
    Note: "NVMe drives should appear automatically in UEFI mode"
  
  # ============================================
  # RAID CONTROLLER (if present)
  # ============================================
  
  Hardware RAID:
    Option A: "Configure RAID in controller BIOS (recommended for HW RAID)"
    Option B: "Set controller to HBA/IT mode for ZFS software RAID"
    Note: "ZFS software RAID is recommended over hardware RAID"
    Reason: "ZFS provides better data integrity and flexibility"
  ```
  :::

  :::accordion-item{icon="i-lucide-monitor" label="3. Boot & Security Settings"}
  ```yaml [Boot Configuration]
  # ============================================
  # BOOT MODE
  # ============================================
  
  Boot Mode:
    Setting: "UEFI (recommended)"
    Location: "Boot → Boot Mode"
    Fallback: "Legacy BIOS (if UEFI not available)"
    Note: "UEFI required for disks > 2TB, Secure Boot, modern features"
  
  Secure Boot:
    Setting: "DISABLED (Proxmox does not support Secure Boot by default)"
    Location: "Security → Secure Boot → Disabled"
    Note: "Can be enabled later with custom keys — not recommended for initial setup"
  
  CSM (Compatibility Support Module):
    Setting: "Disabled (for pure UEFI boot)"
    Note: "Enable only if you have legacy hardware issues"
  
  # ============================================
  # BOOT ORDER
  # ============================================
  
  Boot Priority:
    1st: "USB Device (for installation)"
    2nd: "Internal SSD/NVMe (for normal boot after install)"
    Note: "Change back to SSD after installation"
  
  # ============================================
  # POWER MANAGEMENT
  # ============================================
  
  Wake-on-LAN:
    Setting: "Enabled (recommended for remote management)"
    Location: "Advanced → Network → Wake on LAN"
  
  After Power Failure:
    Setting: "Power On (server auto-starts after power loss)"
    Location: "Advanced → Power Management → AC Power Recovery"
  
  # ============================================
  # OTHER RECOMMENDED SETTINGS
  # ============================================
  
  Hyper-Threading:
    Setting: "Enabled (Intel)"
    Impact: "More virtual CPU cores available for VMs"
  
  Turbo Boost:
    Setting: "Enabled"
    Impact: "Higher single-core performance when needed"
  
  C-States:
    Setting: "Enabled for power saving, Disabled for consistent performance"
    Note: "Disable on latency-sensitive workloads"
  
  Execute Disable Bit (XD/NX):
    Setting: "Enabled"
    Impact: "Security feature — prevents code execution in data memory"
  ```
  :::
::

::tip{to="https://pve.proxmox.com/wiki/Qemu/KVM_Virtual_Machines#_prerequisites"}
Refer to the official Proxmox documentation for detailed hardware requirements and BIOS configuration recommendations.
::

---

## Phase 3 — Installing Proxmox VE

::note
The Proxmox VE installer is a **guided, menu-driven** process. It takes approximately 5-15 minutes depending on hardware speed. The installer will **erase the target disk completely**.
::

### Boot from USB

::steps{level="4"}

#### Step 1: Insert USB and Boot

1. Insert the Proxmox VE bootable USB into the server
2. Power on or restart the server
3. Press the boot menu key (usually **F11**, **F12**, or **ESC**) during POST
4. Select the USB device from the boot menu

#### Step 2: Proxmox VE Boot Menu

After booting from USB, you'll see the **Proxmox VE GRUB boot menu**:

![Proxmox Boot Menu](https://pve.proxmox.com/pve-docs/images/screenshot/pve-grub-menu.png)

```
┌─────────────────────────────────────────────────┐
│          Proxmox VE GNU/Linux                    │
│                                                 │
│  ► Install Proxmox VE (Graphical)        ← SELECT THIS
│    Install Proxmox VE (Terminal UI)              │
│    Advanced Options                              │
│    Install Proxmox VE (Debug Mode)               │
│    Rescue Boot                                   │
│    Test Memory (memtest86+)                      │
│                                                 │
└─────────────────────────────────────────────────┘
```

Select **"Install Proxmox VE (Graphical)"** and press Enter.

::warning
If the graphical installer fails to start (black screen), reboot and select **"Install Proxmox VE (Terminal UI)"** instead. This text-based installer has the same options.
::

::

### Installation Walkthrough

::steps{level="4"}

#### Step 3: Accept EULA

The first screen shows the **End User License Agreement (EULA)**. Read through it and click **"I agree"** to proceed.

![Proxmox EULA](https://pve.proxmox.com/pve-docs/images/screenshot/pve-setup-eula.png)

#### Step 4: Select Target Disk

This is the **most important step** — you're selecting which disk Proxmox will be installed on. **All data on the selected disk will be erased.**

![Proxmox Disk Selection](https://pve.proxmox.com/pve-docs/images/screenshot/pve-setup-disk-setup.png)

::tabs
  :::tabs-item{icon="i-lucide-hard-drive" label="Single Disk (Simple)"}
  ```yaml [Single Disk Configuration]
  # ============================================
  # SIMPLE SETUP — One disk for everything
  # ============================================
  
  Target Harddisk: "/dev/sda (or /dev/nvme0n1)"
  
  # Click "Options" button to configure filesystem:
  
  Filesystem:
    - ext4:    "Simple, reliable, good performance (DEFAULT)"
    - xfs:     "Good for large files, slightly better performance"
    - zfs:     "Best data integrity, snapshots, compression (RECOMMENDED)"
    - btrfs:   "Snapshots support, less mature than ZFS"
  
  # For single disk, ext4 or ZFS (RAID0/single) are good choices
  ```
  :::

  :::tabs-item{icon="i-lucide-database" label="ZFS RAID (Recommended)"}
  ```yaml [ZFS Configuration]
  # ============================================
  # ZFS SETUP — Best data integrity
  # ============================================
  
  # Click "Options" button on disk selection screen
  
  Filesystem: "zfs (RAID1)"  # For 2 disks
  
  ZFS RAID Levels:
    RAID0:   "Striping — maximum speed, NO redundancy (1+ disk)"
    RAID1:   "Mirror — full redundancy (2 disks) ← RECOMMENDED"
    RAID10:  "Striped mirrors — speed + redundancy (4+ disks)"
    RAIDZ1:  "Single parity — survives 1 disk failure (3+ disks)"
    RAIDZ2:  "Double parity — survives 2 disk failures (4+ disks)"
    RAIDZ3:  "Triple parity — survives 3 disk failures (5+ disks)"
  
  # Select disks for the ZFS pool
  Harddisk 0: "/dev/sda"
  Harddisk 1: "/dev/sdb"
  
  # Advanced ZFS options:
  ashift:     "12 (for 4K sector disks — most modern SSDs)"
  compress:   "lz4 (recommended — minimal CPU overhead)"
  checksum:   "on (data integrity verification)"
  copies:     "1 (number of data copies per block)"
  
  # ZFS disk layout:
  hdsize:     "Total disk size to use (leave some spare for overprovisioning)"
  swapsize:   "8 (GB — swap partition size)"
  maxroot:    "Remaining space for root filesystem"
  maxvz:      "0 (use remaining for VM storage — or separate pool)"
  minfree:    "16 (GB — free space reserved on disk)"
  ```
  :::

  :::tabs-item{icon="i-lucide-settings" label="Advanced Disk Options"}
  ```yaml [Advanced Disk Options]
  # ============================================
  # DISK SIZE OPTIONS (click "Options" button)
  # ============================================
  
  hdsize:
    Description: "Total hard disk size to use"
    Default: "Full disk"
    Tip: "Leave ~10% unused for SSD overprovisioning"
    Example: "If 500GB disk → set to 450GB"
  
  swapsize:
    Description: "Swap partition size in GB"
    Default: "Auto (same as RAM, max 8GB)"
    Recommendation: "4-8 GB for most setups"
    Note: "ZFS also uses ARC cache in RAM — less swap needed"
  
  maxroot:
    Description: "Maximum root filesystem size in GB"
    Default: "Remaining space"
    Recommendation: "96-128 GB for root (Proxmox OS + ISOs + templates)"
  
  maxvz:
    Description: "Maximum size for /var/lib/vz (VM/container storage)"
    Default: "Remaining after root"
    Note: "Only applicable for ext4/xfs, ZFS handles this differently"
  
  minfree:
    Description: "Minimum free space to leave on LVM thin pool"
    Default: "16 GB"
    Note: "Required for LVM snapshot operations"
  ```
  :::
::

::caution
**ZFS RAID1 is strongly recommended** for any production or important lab setup. It protects against single disk failure and provides snapshots, compression, and data integrity verification. If you have only one disk, ZFS with single disk still provides compression and snapshots.
::

#### Step 5: Set Location and Timezone

Select your country, timezone, and keyboard layout.

![Proxmox Location Setup](https://pve.proxmox.com/pve-docs/images/screenshot/pve-setup-location.png)

```yaml [Location Settings]
Country:     "Your country"
Timezone:    "Your timezone (e.g., America/New_York, Europe/London, Asia/Singapore)"
Keyboard:    "Your keyboard layout (e.g., en-us)"
```

#### Step 6: Set Root Password and Email

Configure the **root account password** and administrator email address.

![Proxmox Password Setup](https://pve.proxmox.com/pve-docs/images/screenshot/pve-setup-password.png)

```yaml [Admin Account Settings]
Password:         "Strong-P@ssw0rd-Here!"      # At least 12 characters
Confirm Password: "Strong-P@ssw0rd-Here!"
Email:            "admin@yourdomain.com"        # For system notifications
```

::warning
**Use a strong root password!** This password grants full access to the Proxmox hypervisor and all VMs. Use a combination of uppercase, lowercase, numbers, and special characters with at least 12-16 characters.
::

#### Step 7: Network Configuration

This is where you configure the **management network** for the Proxmox host. This IP address will be used to access the web interface.

![Proxmox Network Setup](https://pve.proxmox.com/pve-docs/images/screenshot/pve-setup-network.png)

```yaml [Network Configuration]
Management Interface: "eno1 (or eth0, enp3s0 — your primary NIC)"
Hostname (FQDN):     "pve.yourdomain.local"      # Must be a fully qualified domain name
IP Address (CIDR):    "10.0.0.100/24"             # Static IP for Proxmox host
Gateway:              "10.0.0.1"                   # Your network gateway/router
DNS Server:           "10.0.0.1"                   # Or 8.8.8.8, 1.1.1.1
```

::tip
**Planning your IP scheme:**
- **Proxmox Host:** Static IP (e.g., `10.0.0.100`)
- **VM Network:** Same subnet or separate VLAN
- **Management Access:** Ensure your workstation can reach this IP
- **DNS:** Use your router IP or public DNS (8.8.8.8, 1.1.1.1)
::

#### Step 8: Review and Install

The installer shows a **summary** of all your choices. Review everything carefully.

![Proxmox Install Summary](https://pve.proxmox.com/pve-docs/images/screenshot/pve-setup-summary.png)

```yaml [Installation Summary — Review]
Filesystem:     "zfs (RAID1)"
Disk(s):        "/dev/sda, /dev/sdb"
Country:        "United States"
Timezone:       "America/New_York"
Keyboard:       "en-us"
Email:          "admin@yourdomain.com"
Management NIC: "eno1"
Hostname:       "pve.yourdomain.local"
IP Address:     "10.0.0.100/24"
Gateway:        "10.0.0.1"
DNS:            "8.8.8.8"
```

Click **"Install"** to begin the installation.

#### Step 9: Installation Progress

The installer will:

1. Partition and format the target disk(s)
2. Copy the Proxmox VE filesystem
3. Install GRUB bootloader
4. Configure networking
5. Set up the initial configuration

![Proxmox Installation Progress](https://pve.proxmox.com/pve-docs/images/screenshot/pve-setup-install-success.png)

This typically takes **3-10 minutes** depending on disk speed.

#### Step 10: Reboot

When installation completes:

1. **Remove the USB drive**
2. Click **"Reboot"**
3. The server will boot into Proxmox VE

```
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│  Welcome to the Proxmox Virtual Environment                  │
│                                                              │
│  Please use your web browser to configure this server -      │
│  connect to:                                                 │
│                                                              │
│       https://10.0.0.100:8006/                               │
│                                                              │
│                                                              │
│  pve login: _                                                │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

::

---

## Phase 4 — First Login & Post-Installation

### Access the Web Interface

::steps{level="4"}

#### Step 1: Open Web Browser

From another computer on the same network, open your web browser and navigate to:

```
https://10.0.0.100:8006
```

::caution
You will see a **SSL certificate warning** — this is expected because Proxmox uses a self-signed certificate. Click **"Advanced"** → **"Proceed to site"** (or equivalent in your browser).
::

#### Step 2: Login to Proxmox

![Proxmox Login Screen](https://pve.proxmox.com/pve-docs/images/screenshot/gui-login-window.png)

```yaml [Login Credentials]
Username:   "root"
Password:   "(the password you set during installation)"
Realm:      "Linux PAM standard authentication"
Language:   "English"
```

#### Step 3: Dismiss Subscription Notice

After login, you'll see a **"No valid subscription"** popup. This is normal — Proxmox VE is free to use, the subscription is for enterprise support.

Click **"OK"** to dismiss.

::

### Remove Subscription Nag (Optional)

::collapsible
**Remove Enterprise Repository & Subscription Notice**

```bash [Post-Install Configuration — SSH into Proxmox]
# ============================================
# SSH into your Proxmox host
# ============================================
ssh root@10.0.0.100

# ============================================
# 1. DISABLE ENTERPRISE REPOSITORY (requires subscription)
# ============================================

# Comment out enterprise repo
sed -i 's/^deb/#deb/' /etc/apt/sources.list.d/pve-enterprise.list

# Or remove the file
# mv /etc/apt/sources.list.d/pve-enterprise.list /etc/apt/sources.list.d/pve-enterprise.list.bak

# ============================================
# 2. ADD NO-SUBSCRIPTION REPOSITORY (free)
# ============================================

# Add the no-subscription repository
echo "deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription" > /etc/apt/sources.list.d/pve-no-subscription.list

# ============================================
# 3. DISABLE CEPH ENTERPRISE REPO (if present)
# ============================================

# Comment out Ceph enterprise repo
if [ -f /etc/apt/sources.list.d/ceph.list ]; then
    sed -i 's/^deb/#deb/' /etc/apt/sources.list.d/ceph.list
fi

# ============================================
# 4. UPDATE SYSTEM
# ============================================

apt update && apt full-upgrade -y

# ============================================
# 5. REMOVE SUBSCRIPTION NAG (Optional — cosmetic only)
# ============================================

# Backup the original file
cp /usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js /usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js.bak

# Remove the subscription check popup
sed -Ei.bak "s/res === null \|\| res === undefined \|\| \!res \|\| res\.data\.status\.toLowerCase\(\) !== 'active'/false/g" /usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js

# Restart the web interface
systemctl restart pveproxy

echo "[✓] Post-installation configuration complete"
echo "[✓] Refresh your browser to see changes"
```
::

### System Update

```bash [Update Proxmox VE]
# Always update after fresh installation
apt update && apt full-upgrade -y

# Check Proxmox version
pveversion -v

# Expected output:
# proxmox-ve: 8.4.x (running kernel: 6.8.x-x-pve)
# pve-manager: 8.4.x
# ...

# Reboot if kernel was updated
reboot
```

---

## Phase 5 — Network Configuration

::note{to="https://pve.proxmox.com/pve-docs/chapter-sysadmin.html#_network_configuration"}
Proper network configuration is essential for VM connectivity. Proxmox uses **Linux bridges** to connect VMs to the physical network. Refer to the official network documentation for advanced setups.
::

### Understanding Proxmox Networking

```
┌─────────────────────────────────────────────────────────────┐
│                 PROXMOX NETWORK MODEL                       │
│                                                             │
│  Physical NIC (eno1)                                        │
│       │                                                     │
│       ▼                                                     │
│  ┌─────────────────────────────────────────┐                │
│  │         Linux Bridge (vmbr0)            │                │
│  │         IP: 10.0.0.100/24               │                │
│  │         Gateway: 10.0.0.1               │                │
│  │                                         │                │
│  │    ┌────────┐ ┌────────┐ ┌────────┐     │                │
│  │    │ VM 100 │ │ VM 101 │ │ CT 200 │     │                │
│  │    │ .101   │ │ .102   │ │ .201   │     │                │
│  │    └────────┘ └────────┘ └────────┘     │                │
│  └─────────────────────────────────────────┘                │
│                                                             │
│  All VMs/CTs on vmbr0 share the same network                │
│  as the physical NIC — they get IPs from your               │
│  network's DHCP or use static IPs                           │
└─────────────────────────────────────────────────────────────┘
```

### Default Network Configuration

The installer creates a default bridge (`vmbr0`) connected to your management NIC. View it at:

**Proxmox GUI → Node (pve) → System → Network**

![Proxmox Network Configuration](https://pve.proxmox.com/pve-docs/images/screenshot/gui-node-network.png)

### Network Configuration File

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---

```bash [/etc/network/interfaces]
# ============================================
# DEFAULT PROXMOX NETWORK CONFIGURATION
# Created during installation
# ============================================

auto lo
iface lo inet loopback

# Physical NIC
auto eno1
iface eno1 inet manual

# Primary Linux Bridge (Management + VM network)
auto vmbr0
iface vmbr0 inet static
    address 10.0.0.100/24
    gateway 10.0.0.1
    bridge-ports eno1
    bridge-stp off
    bridge-fd 0

# ============================================
# OPTIONAL: Second bridge for isolated VM network
# ============================================
# auto vmbr1
# iface vmbr1 inet static
#     address 192.168.100.1/24
#     bridge-ports none
#     bridge-stp off
#     bridge-fd 0
#     # No gateway — isolated internal network
#     # VMs on this bridge can only talk to each other
#     # and the Proxmox host (useful for pentesting labs)

# ============================================
# OPTIONAL: VLAN-aware bridge
# ============================================
# auto vmbr0
# iface vmbr0 inet static
#     address 10.0.0.100/24
#     gateway 10.0.0.1
#     bridge-ports eno1
#     bridge-stp off
#     bridge-fd 0
#     bridge-vlan-aware yes
#     bridge-vids 2-4094
```

#code
```bash
# View current network config
cat /etc/network/interfaces

# Apply changes without reboot
ifreload -a
```
::

### Advanced Network Configurations

::tabs
  :::tabs-item{icon="i-lucide-link" label="NIC Bonding (LACP)"}
  ```bash [NIC Bonding Configuration]
  # ============================================
  # BONDING — Combine two NICs for redundancy/speed
  # Requires switch support for LACP (802.3ad)
  # ============================================
  
  # /etc/network/interfaces
  
  auto eno1
  iface eno1 inet manual
  
  auto eno2
  iface eno2 inet manual
  
  # Bond interface
  auto bond0
  iface bond0 inet manual
      bond-slaves eno1 eno2
      bond-miimon 100
      bond-mode 802.3ad          # LACP (requires switch config)
      # bond-mode active-backup  # Failover only (no switch config needed)
      bond-xmit-hash-policy layer3+4
  
  # Bridge on bonded interface
  auto vmbr0
  iface vmbr0 inet static
      address 10.0.0.100/24
      gateway 10.0.0.1
      bridge-ports bond0
      bridge-stp off
      bridge-fd 0
  ```
  :::

  :::tabs-item{icon="i-lucide-network" label="VLAN Configuration"}
  ```bash [VLAN Network Configuration]
  # ============================================
  # VLAN-AWARE BRIDGE
  # Allows VMs to tag traffic with VLAN IDs
  # ============================================
  
  # /etc/network/interfaces
  
  auto eno1
  iface eno1 inet manual
  
  # VLAN-aware bridge
  auto vmbr0
  iface vmbr0 inet static
      address 10.0.0.100/24
      gateway 10.0.0.1
      bridge-ports eno1
      bridge-stp off
      bridge-fd 0
      bridge-vlan-aware yes
      bridge-vids 2-4094
  
  # When creating VMs, set VLAN tag in network settings:
  # VM → Hardware → Network Device → VLAN Tag: 100
  
  # ============================================
  # SEPARATE BRIDGES PER VLAN (alternative)
  # ============================================
  
  # Management VLAN (10)
  auto eno1.10
  iface eno1.10 inet manual
  
  auto vmbr0
  iface vmbr0 inet static
      address 10.0.10.100/24
      gateway 10.0.10.1
      bridge-ports eno1.10
      bridge-stp off
      bridge-fd 0
  
  # VM VLAN (20)
  auto eno1.20
  iface eno1.20 inet manual
  
  auto vmbr1
  iface vmbr1 inet static
      address 10.0.20.1/24
      bridge-ports eno1.20
      bridge-stp off
      bridge-fd 0
  ```
  :::

  :::tabs-item{icon="i-lucide-shield" label="Isolated Lab Network"}
  ```bash [Isolated Pentesting Lab Network]
  # ============================================
  # ISOLATED NETWORK — No external access
  # Perfect for pentesting labs with vulnerable VMs
  # ============================================
  
  # /etc/network/interfaces
  
  # Management bridge (external access)
  auto vmbr0
  iface vmbr0 inet static
      address 10.0.0.100/24
      gateway 10.0.0.1
      bridge-ports eno1
      bridge-stp off
      bridge-fd 0
  
  # Isolated lab bridge (NO physical port — internal only)
  auto vmbr1
  iface vmbr1 inet static
      address 192.168.100.1/24
      bridge-ports none
      bridge-stp off
      bridge-fd 0
  
  # NAT for lab network (optional — give lab internet access)
  # Add to /etc/network/interfaces:
  
  # post-up echo 1 > /proc/sys/net/ipv4/ip_forward
  # post-up iptables -t nat -A POSTROUTING -s '192.168.100.0/24' -o vmbr0 -j MASQUERADE
  # post-down iptables -t nat -D POSTROUTING -s '192.168.100.0/24' -o vmbr0 -j MASQUERADE
  
  # Apply changes
  # ifreload -a
  ```
  :::
::

---

## Phase 6 — Storage Configuration

::tip{to="https://pve.proxmox.com/pve-docs/chapter-pvesm.html"}
Proxmox supports multiple storage types. Understanding storage is crucial for VM performance and data management. See the official storage documentation.
::

### Storage Types Overview

| Storage Type | Content | Snapshots | Speed | Use Case |
| --- | --- | --- | --- | --- |
| **Local (dir)** | All | `No` | `Depends on disk` | Default, simple |
| **LVM** | Disk images | `No` | `Fast` | Block-level storage |
| **LVM-Thin** | Disk images | `Yes` | `Fast` | Thin provisioning, snapshots |
| **ZFS** | All | `Yes` | `Fast` | Best for data integrity |
| **NFS** | All | `No` | `Network` | Shared storage |
| **Ceph** | Disk images | `Yes` | `Fast` | Distributed, HA clusters |

### Default Storage Layout

After installation, Proxmox creates default storage. View at:

**Proxmox GUI → Datacenter → Storage**

![Proxmox Storage](https://pve.proxmox.com/pve-docs/images/screenshot/gui-datacenter-storage.png)

```bash [View Storage Configuration]
# List all storage
pvesm status

# Output example:
# Name             Type     Status  Total     Used    Available  %
# local            dir      active  96G       5G      87G        5.5%
# local-lvm        lvmthin  active  384G      0       384G       0.0%

# Detailed storage info
cat /etc/pve/storage.cfg
```

### Adding Additional Storage

::tabs
  :::tabs-item{icon="i-lucide-hard-drive" label="Add ZFS Pool"}
  ```bash [Create ZFS Storage Pool]
  # ============================================
  # ADD A NEW ZFS POOL FOR VM STORAGE
  # ============================================
  
  # List available disks
  lsblk
  fdisk -l
  
  # Create ZFS pool (mirror of two disks)
  zpool create -f vmpool mirror /dev/sdc /dev/sdd
  
  # Or single disk pool
  # zpool create -f vmpool /dev/sdc
  
  # Or RAIDZ1 (3+ disks)
  # zpool create -f vmpool raidz1 /dev/sdc /dev/sdd /dev/sde
  
  # Enable compression
  zfs set compression=lz4 vmpool
  
  # Set mount point
  zfs set mountpoint=/vmpool vmpool
  
  # ============================================
  # ADD TO PROXMOX VIA GUI
  # ============================================
  # Datacenter → Storage → Add → ZFS
  # ID: vmpool
  # ZFS Pool: vmpool
  # Content: Disk image, Container
  # Thin provision: Yes
  
  # ============================================
  # OR ADD VIA CLI
  # ============================================
  pvesm add zfspool vmpool -pool vmpool -content images,rootdir -sparse 1
  
  # Verify
  pvesm status
  zpool status vmpool
  ```
  :::

  :::tabs-item{icon="i-lucide-folder" label="Add Directory Storage"}
  ```bash [Add Directory Storage]
  # ============================================
  # ADD A DIRECTORY FOR ISOs AND TEMPLATES
  # ============================================
  
  # Create directory
  mkdir -p /mnt/storage/isos
  mkdir -p /mnt/storage/templates
  
  # If using a separate partition, mount it
  # echo "UUID=xxx /mnt/storage ext4 defaults 0 2" >> /etc/fstab
  # mount -a
  
  # Add via GUI:
  # Datacenter → Storage → Add → Directory
  # ID: iso-storage
  # Directory: /mnt/storage
  # Content: ISO image, Container template
  
  # Or via CLI:
  pvesm add dir iso-storage --path /mnt/storage --content iso,vztmpl
  
  # Verify
  pvesm status
  ```
  :::

  :::tabs-item{icon="i-lucide-share-2" label="Add NFS Storage"}
  ```bash [Add NFS Network Storage]
  # ============================================
  # ADD NFS SHARE (from NAS or file server)
  # ============================================
  
  # Ensure NFS client is installed
  apt install -y nfs-common
  
  # Test mount
  mount -t nfs 10.0.0.50:/shared/proxmox /mnt/test
  ls /mnt/test
  umount /mnt/test
  
  # Add via GUI:
  # Datacenter → Storage → Add → NFS
  # ID: nfs-backup
  # Server: 10.0.0.50
  # Export: /shared/proxmox
  # Content: VZDump backup file, ISO image, Container template
  
  # Or via CLI:
  pvesm add nfs nfs-backup \
    --server 10.0.0.50 \
    --export /shared/proxmox \
    --content backup,iso,vztmpl \
    --options vers=4.2
  
  # Verify
  pvesm status
  ```
  :::
::

### Upload ISO Images

You need ISO images to create VMs. Upload them through the web interface:

::steps{level="4"}

#### Navigate to Storage

**Proxmox GUI → Node (pve) → local (pve) → ISO Images → Upload**

#### Upload ISOs

Click **"Upload"** and select your ISO files. Common ISOs you'll need:

::card-group
  ::card
  ---
  title: Ubuntu Server 24.04
  icon: i-simple-icons-ubuntu
  to: https://ubuntu.com/download/server
  target: _blank
  ---
  Download Ubuntu Server LTS ISO for creating Linux VMs and containers.
  ::

  ::card
  ---
  title: Kali Linux
  icon: i-simple-icons-kalilinux
  to: https://www.kali.org/get-kali/#kali-installer-images
  target: _blank
  ---
  Download Kali Linux installer ISO for your pentesting attacker VM.
  ::

  ::card
  ---
  title: Windows Server Eval
  icon: i-simple-icons-windows
  to: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2022
  target: _blank
  ---
  Download Windows Server 2022 evaluation ISO (180-day trial).
  ::

  ::card
  ---
  title: VirtIO Drivers (Windows)
  icon: i-lucide-hard-drive
  to: https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso
  target: _blank
  ---
  Required drivers for Windows VMs to use VirtIO disk and network for best performance.
  ::
::

#### Download ISOs via CLI (Faster)

```bash [Download ISOs via Command Line]
# SSH into Proxmox host
ssh root@10.0.0.100

# Change to ISO storage directory
cd /var/lib/vz/template/iso/

# Download Ubuntu Server
wget https://releases.ubuntu.com/24.04/ubuntu-24.04-live-server-amd64.iso

# Download Kali Linux
wget https://cdimage.kali.org/kali-2024.4/kali-linux-2024.4-installer-amd64.iso

# Download VirtIO drivers (required for Windows VMs)
wget https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso

# Verify downloads
ls -lh /var/lib/vz/template/iso/
```

::

---

## Phase 7 — Creating Your First Virtual Machine

::note{to="https://pve.proxmox.com/pve-docs/chapter-qm.html"}
Proxmox uses **QEMU/KVM** for full virtualization. VMs can run any operating system including Windows, Linux, BSD, and more. See the official QEMU/KVM VM documentation.
::

### Create a Linux VM (Ubuntu)

::steps{level="4"}

#### Step 1: Click "Create VM"

In the Proxmox GUI, click the **"Create VM"** button in the top-right corner.

![Create VM Button](https://pve.proxmox.com/pve-docs/images/screenshot/gui-create-vm-general.png)

#### Step 2: General Settings

```yaml [VM General Settings]
Node:       "pve"                          # Your Proxmox node
VM ID:      "100"                          # Auto-assigned or manual
Name:       "ubuntu-server"                # Descriptive VM name
Resource Pool: "(leave empty or select)"
Start at boot: "Yes (check box)"           # Auto-start on host boot
```

#### Step 3: OS Settings

```yaml [VM OS Settings]
ISO Image:      "local:iso/ubuntu-24.04-live-server-amd64.iso"
Type:           "Linux"
Version:        "6.x - 2.6 Kernel"
```

#### Step 4: System Settings

```yaml [VM System Settings]
Graphic card:    "Default"
Machine:         "q35"                     # Modern chipset (recommended)
BIOS:            "OVMF (UEFI)"            # UEFI boot (recommended)
EFI Storage:     "local-lvm"              # Storage for EFI disk
SCSI Controller: "VirtIO SCSI single"     # Best performance
Qemu Agent:      "Enabled (check box)"    # VM management agent
TPM:             "Add if needed (Windows 11 requires TPM)"
```

::tip
**q35 + UEFI + VirtIO SCSI** is the recommended combination for best performance and modern feature support. Use **SeaBIOS** only for legacy OS compatibility.
::

#### Step 5: Disk Settings

```yaml [VM Disk Settings]
Bus/Device:      "SCSI" (with VirtIO SCSI controller)
Storage:         "local-lvm"              # Or your ZFS pool
Disk size (GiB): "40"                     # Adjust based on needs
Cache:           "Write back"             # Best performance
Discard:         "Enabled"                # TRIM support for SSDs
SSD emulation:   "Enabled"               # If backend is SSD
IO thread:       "Enabled"               # Better IO performance
```

#### Step 6: CPU Settings

```yaml [VM CPU Settings]
Sockets:   "1"
Cores:     "2"                            # Adjust based on workload
Type:      "host"                         # Best performance (native CPU features)
           # Use "x86-64-v2-AES" for migration compatibility
```

#### Step 7: Memory Settings

```yaml [VM Memory Settings]
Memory (MiB):        "4096"               # 4 GB RAM
Minimum memory:      "2048"               # Ballooning minimum (optional)
Ballooning Device:   "Enabled"            # Dynamic memory management
```

#### Step 8: Network Settings

```yaml [VM Network Settings]
Bridge:      "vmbr0"                      # Connect to main bridge
Model:       "VirtIO (paravirtualized)"   # Best performance
VLAN Tag:    "(leave empty or set VLAN)"
Firewall:    "Enabled"                    # Proxmox firewall
MAC Address: "Auto-generated"
Rate limit:  "(optional — MB/s)"
```

#### Step 9: Confirm and Create

Review the summary and click **"Finish"**. Optionally check **"Start after created"** to boot immediately.

#### Step 10: Start and Install OS

1. Select the VM in the left sidebar
2. Click **"Start"** button
3. Click **"Console"** to open the VM console
4. Follow the Ubuntu installer as normal

![Proxmox VM Console](https://pve.proxmox.com/pve-docs/images/screenshot/gui-qemu-summary.png)

::

### Install QEMU Guest Agent

::caution
Always install the **QEMU Guest Agent** inside your VMs. It enables Proxmox to properly manage the VM — graceful shutdown, freeze for snapshots, IP address reporting, and more.
::

```bash [Install QEMU Guest Agent]
# ============================================
# LINUX VMs (Ubuntu/Debian)
# ============================================
sudo apt update
sudo apt install -y qemu-guest-agent
sudo systemctl enable qemu-guest-agent
sudo systemctl start qemu-guest-agent

# ============================================
# LINUX VMs (RHEL/CentOS)
# ============================================
sudo dnf install -y qemu-guest-agent
sudo systemctl enable qemu-guest-agent
sudo systemctl start qemu-guest-agent

# ============================================
# WINDOWS VMs
# ============================================
# 1. Mount the VirtIO ISO as a CD-ROM in Proxmox
# 2. Inside Windows, navigate to the CD-ROM drive
# 3. Run: virtio-win-guest-tools.exe
# 4. This installs VirtIO drivers AND the QEMU guest agent

# Verify from Proxmox host:
qm agent 100 ping
# Returns if agent is responsive
```

### Create a Windows VM

::collapsible
**Windows VM Creation — Special Configuration**

```yaml [Windows VM Settings]
# ============================================
# Windows VMs require special settings for best performance
# ============================================

General:
  Name: "windows-server"
  VM ID: "101"

OS:
  ISO Image: "Windows Server 2022 ISO"
  Type: "Microsoft Windows"
  Version: "11/2022/2025"
  # IMPORTANT: Add VirtIO ISO as additional CD-ROM

System:
  Machine: "q35"
  BIOS: "OVMF (UEFI)"
  EFI Storage: "local-lvm"
  TPM: "v2.0"                    # Required for Windows 11
  SCSI Controller: "VirtIO SCSI single"
  Qemu Agent: "Enabled"

Disks:
  Main Disk:
    Bus: "SCSI"                  # VirtIO SCSI for best performance
    Size: "80 GiB"
    Cache: "Write back"
    Discard: "Enabled"
    SSD emulation: "Enabled"
  CD-ROM 1:
    Bus: "IDE 0"
    Image: "Windows ISO"
  CD-ROM 2:
    Bus: "IDE 1"                  
    Image: "virtio-win.iso"      # VirtIO drivers

CPU:
  Cores: "4"
  Type: "host"

Memory:
  RAM: "8192 MiB"               # 8 GB minimum for Windows Server

Network:
  Model: "VirtIO (paravirtualized)"
  Bridge: "vmbr0"

# ============================================
# DURING WINDOWS INSTALLATION:
# ============================================
# 1. Windows won't see the VirtIO SCSI disk initially
# 2. Click "Load driver" when asked to select disk
# 3. Browse to CD-ROM 2 (VirtIO ISO)
# 4. Navigate to: vioscsi\2k22\amd64 (or appropriate folder)
# 5. Select the VirtIO SCSI driver
# 6. Windows will now see the disk — proceed with installation
# 7. After Windows is installed, install all VirtIO drivers
#    from the VirtIO ISO (run virtio-win-guest-tools.exe)
```
::

---

## Phase 8 — Creating LXC Containers

::note{to="https://pve.proxmox.com/pve-docs/chapter-pct.html"}
LXC containers are **lightweight alternatives to VMs** — they share the host kernel and use far less resources. Perfect for running services like web servers, databases, Docker, etc.
::

### Download Container Templates

::steps{level="4"}

#### Step 1: Download Templates

**Proxmox GUI → Node (pve) → local → CT Templates → Templates**

Click **"Templates"** to see available templates and download them.

```bash [Download Templates via CLI]
# List available templates
pveam available --section system

# Download Ubuntu template
pveam download local ubuntu-24.04-standard_24.04-2_amd64.tar.zst

# Download Debian template
pveam download local debian-12-standard_12.7-1_amd64.tar.zst

# Download Alpine template (very lightweight)
pveam download local alpine-3.20-default_20240908_amd64.tar.xz

# List downloaded templates
pveam list local
```

#### Step 2: Create Container

**Proxmox GUI → "Create CT" button (top-right)**

```yaml [LXC Container Settings]
General:
  CT ID: "200"
  Hostname: "nginx-server"
  Password: "SecurePass123!"
  SSH public key: "(paste your public key)"
  Unprivileged: "Yes (recommended for security)"
  Nesting: "Enable if running Docker inside container"

Template:
  Storage: "local"
  Template: "ubuntu-24.04-standard"

Disks:
  Root Disk:
    Storage: "local-lvm"
    Size: "8 GiB"

CPU:
  Cores: "2"

Memory:
  RAM: "2048 MiB"
  Swap: "512 MiB"

Network:
  Name: "eth0"
  Bridge: "vmbr0"
  IPv4: "DHCP"                 # Or static: 10.0.0.201/24
  Gateway: "10.0.0.1"         # Only if static
  IPv6: "DHCP" or "Static"

DNS:
  Domain: "yourdomain.local"
  DNS servers: "8.8.8.8 1.1.1.1"
```

::

### Container vs VM — When to Use What

| Feature | LXC Container | KVM Virtual Machine |
| --- | --- | --- |
| **Boot time** | `Seconds` | `30-60 seconds` |
| **RAM overhead** | `~20 MB` | `~256+ MB` |
| **Disk overhead** | `Minimal` | `Full OS install` |
| **OS support** | `Linux only` | `Any OS (Windows, BSD, etc.)` |
| **Kernel** | `Shares host kernel` | `Own kernel` |
| **Isolation** | `Process-level` | `Full hardware-level` |
| **Performance** | `Near-native` | `Near-native (with VirtIO)` |
| **Use case** | `Web servers, databases, Docker` | `Windows, desktop, full isolation` |
| **Security** | `Good (unprivileged)` | `Best (full isolation)` |
| **GPU passthrough** | `Limited` | `Full support` |

---

## Phase 9 — Backup & Snapshot Configuration

::warning
**Backups are not optional.** Configure automated backups immediately after setting up your first VMs. A single disk failure without backups means complete data loss.
::

### Snapshot Management

```bash [VM Snapshots]
# ============================================
# CREATE SNAPSHOT (via CLI)
# ============================================

# Snapshot VM 100 with memory state
qm snapshot 100 clean-install --description "Fresh OS install before configuration"

# Snapshot without memory (faster, smaller)
qm snapshot 100 pre-update --vmstate 0 --description "Before system update"

# ============================================
# LIST SNAPSHOTS
# ============================================
qm listsnapshot 100

# ============================================
# ROLLBACK TO SNAPSHOT
# ============================================
qm rollback 100 clean-install

# ============================================
# DELETE SNAPSHOT
# ============================================
qm delsnapshot 100 pre-update

# ============================================
# CONTAINER SNAPSHOTS (same concept)
# ============================================
pct snapshot 200 initial-setup
pct listsnapshot 200
pct rollback 200 initial-setup
```

### Automated Backup Schedule

::steps{level="4"}

#### Configure Backup Job

**Proxmox GUI → Datacenter → Backup → Add**

```yaml [Backup Job Configuration]
# ============================================
# Via GUI: Datacenter → Backup → Add
# ============================================

General:
  Node: "pve"                    # Or --all for cluster
  Storage: "local"               # Backup storage target
  Schedule: "daily"              # Or: sun 02:00, */6:00
  Selection mode: "All"          # All VMs/CTs or specific IDs
  
Retention:
  Keep Last: "3"                 # Keep last 3 backups
  Keep Daily: "7"                # Keep daily for 7 days
  Keep Weekly: "4"               # Keep weekly for 4 weeks
  Keep Monthly: "3"              # Keep monthly for 3 months
  
Settings:
  Mode: "Snapshot"               # snapshot/suspend/stop
  Compression: "ZSTD"           # Best compression ratio
  Notification: "Always"        # Email on success/failure
```

#### Manual Backup via CLI

```bash [Manual Backup Commands]
# Backup VM 100
vzdump 100 --storage local --compress zstd --mode snapshot

# Backup container 200
vzdump 200 --storage local --compress zstd --mode snapshot

# Backup all VMs and containers
vzdump --all --storage local --compress zstd --mode snapshot

# List backups
ls -lh /var/lib/vz/dump/

# Restore VM from backup
qmrestore /var/lib/vz/dump/vzdump-qemu-100-2024_01_01-02_00_00.vma.zst 100

# Restore container from backup
pct restore 200 /var/lib/vz/dump/vzdump-lxc-200-2024_01_01-02_00_00.tar.zst
```

::

---

## Phase 10 — Security Hardening

::tip{to="https://pve.proxmox.com/pve-docs/chapter-pvesm.html"}
Proxmox is a critical infrastructure component — if the hypervisor is compromised, ALL VMs are compromised. Harden it thoroughly.
::

### Proxmox Security Configuration

::tabs
  :::tabs-item{icon="i-lucide-shield" label="Firewall"}
  ```bash [Proxmox Firewall Configuration]
  # ============================================
  # ENABLE PROXMOX BUILT-IN FIREWALL
  # ============================================
  
  # Via GUI: Datacenter → Firewall → Options → Enable: Yes
  # Via GUI: Node → Firewall → Options → Enable: Yes
  
  # ============================================
  # DATACENTER-LEVEL RULES
  # /etc/pve/firewall/cluster.fw
  # ============================================
  
  cat > /etc/pve/firewall/cluster.fw << 'EOF'
  [OPTIONS]
  enable: 1
  policy_in: DROP
  policy_out: ACCEPT
  
  [RULES]
  # Allow Proxmox Web GUI (from admin network only)
  IN ACCEPT -source 10.0.0.0/24 -p tcp -dport 8006 -log nolog
  
  # Allow SSH (from admin network only)
  IN ACCEPT -source 10.0.0.0/24 -p tcp -dport 22 -log nolog
  
  # Allow SPICE console
  IN ACCEPT -source 10.0.0.0/24 -p tcp -dport 3128 -log nolog
  
  # Allow VNC console
  IN ACCEPT -source 10.0.0.0/24 -p tcp -dport 5900:5999 -log nolog
  
  # Allow Proxmox cluster communication (if clustered)
  IN ACCEPT -source 10.0.0.0/24 -p tcp -dport 5404:5405 -log nolog
  IN ACCEPT -source 10.0.0.0/24 -p udp -dport 5404:5405 -log nolog
  IN ACCEPT -source 10.0.0.0/24 -p tcp -dport 2049 -log nolog
  
  # Allow ICMP (ping)
  IN ACCEPT -p icmp -log nolog
  
  # Log dropped packets
  IN DROP -log nolog
  EOF
  
  # Apply firewall
  pve-firewall restart
  pve-firewall status
  ```
  :::

  :::tabs-item{icon="i-lucide-key" label="SSH & Access Control"}
  ```bash [SSH & Access Hardening]
  # ============================================
  # SSH HARDENING
  # ============================================
  
  cat > /etc/ssh/sshd_config.d/hardening.conf << 'EOF'
  # Disable root login (use non-root user + sudo)
  # PermitRootLogin no     # Enable after creating non-root admin user
  
  # Key-only authentication
  PasswordAuthentication no
  ChallengeResponseAuthentication no
  
  # Restrict to admin network
  # AllowUsers admin@10.0.0.*
  
  # Security settings
  MaxAuthTries 3
  MaxSessions 3
  X11Forwarding no
  AllowAgentForwarding no
  ClientAliveInterval 300
  ClientAliveCountMax 2
  LoginGraceTime 30
  
  # Strong ciphers
  Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
  MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
  EOF
  
  systemctl restart sshd
  
  # ============================================
  # CREATE NON-ROOT ADMIN USER
  # ============================================
  
  # Create user
  useradd -m -s /bin/bash pvadmin
  passwd pvadmin
  
  # Add to sudo group
  usermod -aG sudo pvadmin
  
  # Add SSH key
  mkdir -p /home/pvadmin/.ssh
  echo "ssh-ed25519 YOUR_PUBLIC_KEY" > /home/pvadmin/.ssh/authorized_keys
  chown -R pvadmin:pvadmin /home/pvadmin/.ssh
  chmod 700 /home/pvadmin/.ssh
  chmod 600 /home/pvadmin/.ssh/authorized_keys
  
  # ============================================
  # ADD PROXMOX USER (for GUI access)
  # ============================================
  
  # Add PAM user to Proxmox
  pveum user add pvadmin@pam
  
  # Assign Administrator role
  pveum acl modify / -user pvadmin@pam -role Administrator
  
  # Now login to GUI with pvadmin@pam
  ```
  :::

  :::tabs-item{icon="i-lucide-lock" label="Two-Factor Authentication"}
  ```bash [Enable 2FA for Proxmox]
  # ============================================
  # TOTP TWO-FACTOR AUTHENTICATION
  # ============================================
  
  # Via GUI:
  # 1. Login to Proxmox
  # 2. Click your username (top right)
  # 3. Click "TFA" (Two Factor Authentication)
  # 4. Click "Add" → Select "TOTP"
  # 5. Scan QR code with authenticator app
  #    (Google Authenticator, Authy, etc.)
  # 6. Enter verification code
  # 7. Save
  
  # Via CLI:
  # Generate TOTP secret
  pveum user token add root@pam totp-token
  
  # ============================================
  # WEBAUTHN / FIDO2 (Hardware Key)
  # ============================================
  
  # Via GUI:
  # 1. Click username → TFA → Add → WebAuthn
  # 2. Insert YubiKey or other FIDO2 key
  # 3. Follow browser prompts
  
  # ============================================
  # ENFORCE 2FA FOR ALL USERS
  # ============================================
  
  # Datacenter → Permissions → Two Factor → Options
  # Require TFA: Yes
  ```
  :::
::

### Fail2Ban for Proxmox

::collapsible
**Fail2Ban Configuration for Proxmox Web GUI**

```bash [Fail2Ban for Proxmox]
# Install Fail2Ban
apt install -y fail2ban

# Create Proxmox jail
cat > /etc/fail2ban/jail.d/proxmox.conf << 'EOF'
[proxmox]
enabled = true
port = https,http,8006
filter = proxmox
backend = systemd
maxretry = 3
findtime = 600
bantime = 3600

[sshd]
enabled = true
port = ssh
maxretry = 3
findtime = 600
bantime = 86400
EOF

# Create Proxmox filter
cat > /etc/fail2ban/filter.d/proxmox.conf << 'EOF'
[Definition]
failregex = pvedaemon\[.*authentication failure; rhost=<HOST> user=.* msg=.*
ignoreregex =
journalmatch = _SYSTEMD_UNIT=pvedaemon.service
EOF

# Restart Fail2Ban
systemctl enable fail2ban
systemctl restart fail2ban

# Check status
fail2ban-client status proxmox
fail2ban-client status sshd

# View banned IPs
fail2ban-client get proxmox banned
```
::

---

## Phase 11 — Performance Optimization

### CPU & Memory Tuning

::collapsible
**Performance Optimization Settings**

```bash [Proxmox Performance Tuning]
# ============================================
# CPU GOVERNOR — Set to Performance
# ============================================

# Check current governor
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor

# Set to performance
echo "performance" | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Make persistent
apt install -y cpufrequtils
echo 'GOVERNOR="performance"' > /etc/default/cpufrequtils
systemctl restart cpufrequtils

# ============================================
# ZFS ARC CACHE TUNING
# ============================================

# Check current ARC size
arc_summary | head -30

# Set maximum ARC size (leave RAM for VMs!)
# Rule: Total RAM - (RAM for VMs) - 2GB system = ARC max
# Example: 64GB total - 48GB for VMs - 2GB system = 14GB ARC

echo "options zfs zfs_arc_max=15032385536" > /etc/modprobe.d/zfs.conf
# 15032385536 bytes = ~14 GB

# Apply without reboot
echo 15032385536 > /sys/module/zfs/parameters/zfs_arc_max

# ============================================
# HUGEPAGES (for large VMs)
# ============================================

# Enable transparent hugepages
echo always > /sys/kernel/mm/transparent_hugepage/enabled

# Or allocate static hugepages
# echo 1024 > /proc/sys/vm/nr_hugepages  # 1024 × 2MB = 2GB

# ============================================
# IO SCHEDULER (for SSDs)
# ============================================

# Check current scheduler
cat /sys/block/sda/queue/scheduler

# Set to none (best for NVMe) or mq-deadline (for SATA SSD)
echo none > /sys/block/nvme0n1/queue/scheduler
echo mq-deadline > /sys/block/sda/queue/scheduler

# ============================================
# NETWORK TUNING
# ============================================

cat >> /etc/sysctl.d/99-network-tuning.conf << 'EOF'
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 5000
EOF

sysctl -p /etc/sysctl.d/99-network-tuning.conf
```
::

---

## Useful CLI Commands Reference

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---

```bash [Proxmox CLI Quick Reference]
# ============================================
# VM MANAGEMENT
# ============================================
qm list                          # List all VMs
qm start 100                     # Start VM 100
qm stop 100                      # Stop VM 100 (hard)
qm shutdown 100                  # Graceful shutdown
qm reboot 100                    # Reboot VM
qm reset 100                     # Hard reset
qm suspend 100                   # Suspend (pause) VM
qm resume 100                    # Resume suspended VM
qm destroy 100 --purge           # Delete VM and disks
qm config 100                    # Show VM configuration
qm set 100 --memory 8192         # Change RAM
qm set 100 --cores 4             # Change CPU cores
qm monitor 100                   # Open QEMU monitor
qm agent 100 ping                # Ping QEMU agent

# ============================================
# CONTAINER MANAGEMENT
# ============================================
pct list                         # List all containers
pct start 200                    # Start container
pct stop 200                     # Stop container
pct shutdown 200                 # Graceful shutdown
pct destroy 200 --purge          # Delete container
pct config 200                   # Show config
pct set 200 --memory 4096        # Change RAM
pct enter 200                    # Enter container shell
pct exec 200 -- apt update       # Run command in container

# ============================================
# STORAGE
# ============================================
pvesm status                     # Storage status
pvesm list local                 # List content in storage
zpool status                     # ZFS pool status
zfs list                         # ZFS filesystems
df -h                            # Disk usage

# ============================================
# CLUSTER & NODE
# ============================================
pvecm status                     # Cluster status
pveversion -v                    # Proxmox version info
pveperf                          # Performance benchmark
systemctl status pve*            # Proxmox services status

# ============================================
# BACKUP
# ============================================
vzdump 100 --storage local --compress zstd --mode snapshot
vzdump --all --storage local --compress zstd
```

#code
```bash
# Essential daily commands
qm list && pct list
pvesm status
zpool status
pveversion -v
```
::

---

## Troubleshooting

::accordion
  :::accordion-item{icon="i-lucide-monitor-off" label="VM Console Shows Black Screen"}
  ```bash [Console Troubleshooting]
  # Try different display types
  # VM → Hardware → Display → Change to:
  # - Default (std)
  # - VirtIO-GPU
  # - SPICE (qxl)
  # - VMware compatible (vmware)
  
  # For UEFI VMs, ensure EFI disk is created
  qm set 100 --efidisk0 local-lvm:1
  
  # Try noVNC console vs SPICE console
  # Or use xterm.js (serial terminal)
  
  # Add serial console
  qm set 100 --serial0 socket
  ```
  :::

  :::accordion-item{icon="i-lucide-wifi-off" label="VM Has No Network"}
  ```bash [Network Troubleshooting]
  # Verify bridge exists
  brctl show
  ip link show vmbr0
  
  # Check VM network config
  qm config 100 | grep net
  
  # Verify bridge has physical port
  cat /etc/network/interfaces | grep -A5 vmbr0
  
  # Check if interface is up inside VM
  # Console into VM:
  ip link show
  ip addr show
  dhclient -v eth0  # Try getting DHCP
  
  # Check Proxmox firewall (might be blocking)
  pve-firewall status
  # Temporarily disable to test:
  # Datacenter → Firewall → Options → Enable: No
  ```
  :::

  :::accordion-item{icon="i-lucide-hard-drive" label="Storage Issues"}
  ```bash [Storage Troubleshooting]
  # Check disk health
  smartctl -a /dev/sda
  
  # ZFS pool status
  zpool status -v
  zpool iostat -v 1
  
  # Check for ZFS errors
  zpool scrub rpool    # Start scrub
  zpool status rpool   # Check scrub progress
  
  # LVM status
  lvs
  vgs
  pvs
  
  # Free space on LVM thin pool
  lvs -a | grep thin
  
  # If thin pool is full:
  lvextend -L +50G /dev/pve/data
  ```
  :::

  :::accordion-item{icon="i-lucide-lock" label="Locked Out of Web GUI"}
  ```bash [Access Recovery]
  # SSH into Proxmox host directly
  ssh root@10.0.0.100
  
  # Reset root password
  passwd root
  
  # Restart web interface
  systemctl restart pveproxy
  
  # Check if port 8006 is listening
  ss -tlnp | grep 8006
  
  # Check firewall
  pve-firewall status
  iptables -L -n | grep 8006
  
  # Temporarily disable firewall
  pve-firewall stop
  
  # Check web proxy logs
  journalctl -u pveproxy --since "1 hour ago"
  
  # If HTTPS certificate issue:
  pvecm updatecerts -f
  systemctl restart pveproxy
  ```
  :::
::

---

## References & Resources

::card-group
  ::card
  ---
  title: Proxmox VE Admin Guide
  icon: i-lucide-book-open
  to: https://pve.proxmox.com/pve-docs/pve-admin-guide.html
  target: _blank
  ---
  The complete official administration guide covering every Proxmox VE feature in detail.
  ::

  ::card
  ---
  title: Proxmox VE Wiki
  icon: i-lucide-book-marked
  to: https://pve.proxmox.com/wiki/Main_Page
  target: _blank
  ---
  Community wiki with tutorials, HOWTOs, and troubleshooting guides.
  ::

  ::card
  ---
  title: Proxmox VE API Documentation
  icon: i-lucide-code
  to: https://pve.proxmox.com/pve-docs/api-viewer/
  target: _blank
  ---
  Complete REST API reference for automating Proxmox management.
  ::

  ::card
  ---
  title: Proxmox Forum
  icon: i-lucide-message-circle
  to: https://forum.proxmox.com/
  target: _blank
  ---
  Active community forum with expert support and discussions.
  ::

  ::card
  ---
  title: Proxmox VE Installation (Official)
  icon: i-lucide-download
  to: https://pve.proxmox.com/pve-docs/chapter-pve-installation.html
  target: _blank
  ---
  Official installation documentation with all options and requirements.
  ::

  ::card
  ---
  title: Proxmox Helper Scripts
  icon: i-simple-icons-github
  to: https://tteck.github.io/Proxmox/
  target: _blank
  ---
  Community scripts for automating LXC container creation and Proxmox management.
  ::
::

::warning
**Important Reminders:**
- **Always have backups** before making changes to the Proxmox host
- **Test updates** on a non-production node first when running clusters
- **Keep the host updated** — `apt update && apt full-upgrade -y` regularly
- **Monitor disk health** — `smartctl -a /dev/sdX` and `zpool status`
- **Secure the web interface** — 2FA, firewall, and Fail2Ban
- **Document your configuration** — network, storage, and VM assignments
::