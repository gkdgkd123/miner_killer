# Linux Miner Killer & System Audit Script

这是一个用于 Linux 服务器的应急响应脚本，主要用于检测和清除挖矿病毒、后门账户、恶意进程及持久化攻击。它集成了进程查杀、Docker 检查、系统完整性校验等功能。

## ⚠️ 免责声明 / Disclaimer

**本脚本涉及文件删除和进程终止操作，请在执行前务必确认。作者不对因使用本脚本导致的数据丢失或系统故障负责。建议在执行前备份重要数据。**

**Use at your own risk.** verify commands before confirming deletions.

## 🚀 功能特性 (Features)

1.  **进程查杀**: 自动发现高 CPU 占用、恶意网络连接或包含恶意关键字（如 xmrig, kinsing）的进程。
2.  **网络与端口**: 扫描异常的 ESTABLISHED 连接和监听端口。
3.  **Docker 安全**: 扫描并允许停止/删除高资源占用的恶意容器。
4.  **PM2 守护进程**: 检测被 PM2 隐藏的恶意 Node.js 进程。
5.  **持久化检测**:
    * 扫描 Crontab (定时任务)。
    * 扫描 Systemd 服务文件 (检测恶意启动项)。
    * 扫描 Shell 启动文件 (.bashrc, .profile 等)。
6.  **系统完整性**:
    * `/etc/hosts` 劫持检测。
    * `/etc/passwd` 账户审计 (列出所有 bash/sh 用户)。
    * SSH `authorized_keys` 扫描。
7.  **Rootkit 痕迹**: 检测 `LD_PRELOAD`、内核模块污染及隐藏文件。
8.  **隔离备份**: 删除的恶意文件会自动备份到 `/tmp/malware_quarantine_timestamp`。

## 🛠️ 使用方法 (Usage)

### 方式 1: 直接下载运行 (推荐)

```bash
curl -O [https://raw.githubusercontent.com/你的用户名/你的仓库名/main/miner_killer.sh](https://raw.githubusercontent.com/你的用户名/你的仓库名/main/miner_killer.sh)
chmod +x miner_killer.sh
sudo ./miner_killer.sh
