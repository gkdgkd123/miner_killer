#!/bin/bash
# ==============================================================================
# Project: Linux Miner Killer (Multi-User SSH & Account Audit)
# Usage: bash /tmp/.check.sh
# ==============================================================================

# --- 0. 环境初始化 ---
set -u
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; NC=''
fi

LOG_FILE="/var/log/miner_killer_$(date +%Y%m%d_%H%M%S).log"
BACKUP_DIR=$(mktemp -d /tmp/malware_quarantine.XXXXXX) || { echo "Failed to create backup dir"; exit 1; }
LOCK_FILE="/tmp/miner_killer.lock"

# --- IP 情报查询配置 ---
IPINFO_API_KEY="a3b3be25941f14415ba93648ea46308cd5f9d6d7c256dc4753a351eaf8cc9b0e"  # 官方免费 key

# --- 恶意特征库 ---
MALWARE_KEYWORDS="miner|pool|xmrig|kinsing|c3pool|nanopool|f2pool|stratum|wallet|crypto|eth|xmr|monero|ocean|nicehash|hash|coins|pZzQ|azbQ|kdevtmpfs|java-c|log_rot|watchbog|kthrotlds"

# --- 极简白名单 ---
WHITELIST="systemd-journal|systemd-udevd|dbus-daemon"

# --- 信号捕捉与锁机制 ---
cleanup() {
    rm -f "$LOCK_FILE"
    tput cnorm 2>/dev/null
}

ctrl_c() {
    echo -e "\n${RED}[!] Keyboard Interrupt (Ctrl+C). Exiting...${NC}"
    cleanup
    exit 1
}

on_exit() {
    cleanup
    echo -e "\n${BLUE}Scan Session Ended. Log saved to: $LOG_FILE${NC}"
}

trap ctrl_c INT TERM
trap on_exit EXIT

if [ -f "$LOCK_FILE" ]; then
    echo -e "${RED}[!] Script is already running! (Lockfile: $LOCK_FILE)${NC}"
    exit 1
fi
touch "$LOCK_FILE"

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

# --- 基础工具函数 ---
log() {
    local msg="$1"
    echo -e "$msg"
    printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$(echo -e "$msg" | sed 's/\x1b\[[0-9;]*m//g')" >> "$LOG_FILE"
}

header() {
    echo -e "${BLUE}============================================================${NC}"
    log "${YELLOW}$1${NC}"
    echo -e "${BLUE}============================================================${NC}"
}

ask() {
    local prompt="$1"
    local var_name="$2"
    printf -v "$var_name" ''
    echo -ne "${YELLOW}${prompt}${NC}" > /dev/tty
    read -r "$var_name" < /dev/tty
}

has_cmd() { command -v "$1" >/dev/null 2>&1; }

check_root() {
    if [ "$EUID" -ne 0 ]; then echo -e "${RED}Error: Must run as root.${NC}"; exit 1; fi
}

is_safe_path() {
    local path="$1"
    local safe_dirs="/tmp /var/tmp /dev/shm /root /home /etc/systemd /usr/lib/systemd /etc/ld.so.preload"
    for dir in $safe_dirs; do
        if [[ "$path" == "$dir"* ]]; then
            return 0
        fi
    done
    return 1
}

quarantine_and_remove() {
    local target="$1"
    # 仅去除 " (deleted)" 后缀（内核对已删除文件的标记），保留路径中的空格
    target="${target% (deleted)}"
    # 去除首尾空白
    target=$(echo "$target" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    if [ -z "$target" ]; then return; fi

    if ! is_safe_path "$target"; then
        log "${RED}[X] Unsafe path, skipping: $target${NC}"
        return
    fi

    if [ -e "$target" ] || [ -L "$target" ]; then
        if has_cmd chattr; then chattr -R -i -a "$target" 2>/dev/null; fi
        chmod -R -x "$target" 2>/dev/null
        if [ -f "$target" ] || [ -d "$target" ]; then
            safe_name=$(basename "$target" | sed 's/[^a-zA-Z0-9._-]/_/g')_$(date +%s)
            if cp -rp "$target" "$BACKUP_DIR/$safe_name" 2>/dev/null; then
                log "[Safe] Quarantined to: $BACKUP_DIR/$safe_name"
            else
                log "${RED}[!] Failed to backup: $target${NC}"
            fi
        fi
        if rm -rf "$target"; then
            log "${GREEN}[✔] Deleted: $target${NC}"
        else
            log "${RED}[X] Failed to delete: $target${NC}"
        fi
    else
        log "${CYAN}[-] Target not found: $target${NC}"
    fi
}

find_service_file() {
    local pid=$1
    if ! has_cmd systemctl; then echo ""; return; fi
    local svc_path=$(systemctl status "$pid" 2>/dev/null | grep "Loaded:" | grep -o '(/.*)' | awk '{print $1}' | tr -d '();')
    if [ -z "$svc_path" ]; then
        local unit_name=$(ps -p "$pid" -o unit= 2>/dev/null)
        if [[ "$unit_name" == *.service ]]; then
            svc_path=$(systemctl show -p FragmentPath "$unit_name" 2>/dev/null | cut -d= -f2)
        fi
    fi
    echo "$svc_path"
}

# --- IP 情报查询函数 ---
get_ip_info() {
    local ip="$1"

    # 私有 IP 过滤
    if [[ "$ip" =~ ^127\. ]] || [[ "$ip" =~ ^10\. ]] || [[ "$ip" =~ ^192\.168\. ]] || [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]]; then
        echo "[Private IP]"
        return
    fi

    # 构建 API 请求
    local api_url="https://ipinfo.dkly.net/api/v1/ip/$ip"
    local curl_opts="-s --connect-timeout 3"

    if [ -n "$IPINFO_API_KEY" ]; then
        curl_opts="$curl_opts -H \"Authorization: Bearer $IPINFO_API_KEY\""
    fi

    # 执行 API 请求
    local response=$(eval "curl $curl_opts '$api_url'" 2>/dev/null)

    if [ -z "$response" ]; then
        echo "[API Request Failed]"
        return
    fi

    # 无 jq 环境下的 JSON 解析（使用 grep + sed）
    local country=$(echo "$response" | grep -o '"country":"[^"]*"' | head -1 | cut -d'"' -f4)
    local city=$(echo "$response" | grep -o '"city":"[^"]*"' | head -1 | cut -d'"' -f4)
    local company=$(echo "$response" | grep -o '"name":"[^"]*"' | head -1 | cut -d'"' -f4)

    # 安全标签检查
    local security_tags=""

    [[ "$response" =~ "is_threat":true ]] && security_tags="${security_tags}THREAT/"
    [[ "$response" =~ "is_abuser":true ]] && security_tags="${security_tags}ABUSER/"
    [[ "$response" =~ "is_attacker":true ]] && security_tags="${security_tags}ATTACKER/"
    [[ "$response" =~ "is_tor":true ]] && security_tags="${security_tags}TOR/"
    [[ "$response" =~ "is_proxy":true ]] && security_tags="${security_tags}PROXY/"
    [[ "$response" =~ "is_vpn":true ]] && security_tags="${security_tags}VPN/"

    # 组装返回值
    local result=""

    if [ -n "$country" ] || [ -n "$city" ] || [ -n "$company" ]; then
        result="["
        [ -n "$country" ] && result="${result}${country}"
        if [ -n "$city" ]; then
            [ -n "$country" ] && result="${result}, "
            result="${result}${city}"
        fi
        if [ -n "$company" ]; then
            result="${result} | ${company}"
        fi
        result="${result}]"
    fi

    if [ -n "$security_tags" ]; then
        # 移除末尾的 /
        security_tags="${security_tags%/}"
        result="${result} [⚠️ ${security_tags}]"
    fi

    if [ -z "$result" ]; then
        echo "[API Request Failed]"
    else
        echo "$result"
    fi
}

# --- 0. 态势感知 ---
scan_overview() {
    header "0. System Overview & Panorama"
    log "${CYAN}[*] System Load & Uptime:${NC}"
    uptime
    echo ""
    log "${CYAN}[*] Active Users (who):${NC}"
    w
    echo ""
    
    log "${CYAN}[*] Last 10 Logins (Check for strange IPs):${NC}"
    if has_cmd last; then last -n 10 | head -n 10; else echo "Command 'last' not found."; fi
    echo ""

    log "${CYAN}[*] Listening Ports (Check for backdoors/miners):${NC}"
    if has_cmd netstat; then netstat -tulnp; elif has_cmd ss; then ss -tulnp; else echo -e "${RED}Error: Neither 'netstat' nor 'ss' found.${NC}"; fi
    echo ""
    log "${CYAN}[*] DNS Servers (/etc/resolv.conf):${NC}"
    grep "nameserver" /etc/resolv.conf 2>/dev/null
    echo ""
    ask "Press Enter to start SCAN..." dummy
}

# --- 1. 进程查杀 ---
scan_process() {
    header "1. Process Analysis"
    local CPU_THRESHOLD=8.0
    log "Scanning processes (Logic: CPU>${CPU_THRESHOLD}% OR Network OR Keywords)..."

    # CPU: 筛选所有超过阈值的进程，不限数量
    cpu_pids=$(ps -eo pid,%cpu --sort=-%cpu 2>/dev/null | awk -v t="$CPU_THRESHOLD" 'NR>1 && $2+0 > t {print $1}')
    # Keyword: 匹配恶意特征库，不限数量
    keyword_pids=$(pgrep -f -i "$MALWARE_KEYWORDS" 2>/dev/null)

    net_pids=""
    if has_cmd netstat; then
        net_pids=$(netstat -antp 2>/dev/null | grep 'ESTABLISHED' | grep -v '127.0.0.1' | grep -v 'sshd' | awk '{print $7}' | cut -d/ -f1 | grep -v '^-$')
    elif has_cmd ss; then
        net_pids=$(ss -antp 2>/dev/null | grep 'ESTABLISHED' | grep -v '127.0.0.1' | grep -v 'sshd' | awk '{print $6}' | cut -d, -f2 | grep -v '^-$')
    fi

    all_pids=$(printf '%s\n' $cpu_pids $keyword_pids $net_pids | sort -u | grep -v '^$')

    for pid in $all_pids; do
        if ! [[ "$pid" =~ ^[0-9]+$ ]] || [ ! -d "/proc/$pid" ]; then continue; fi
        ppid=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')
        if [ "$ppid" = "2" ]; then continue; fi

        proc_name=$(ps -p "$pid" -o comm= 2>/dev/null)
        if echo "$proc_name" | grep -iqE "$WHITELIST"; then continue; fi

        cpu_usage=$(ps -p "$pid" -o %cpu= 2>/dev/null | tr -d ' ')
        exe_path=""; if has_cmd readlink; then exe_path=$(readlink -f /proc/$pid/exe 2>/dev/null); fi
        [ -z "$exe_path" ] && exe_path=$(ls -l /proc/$pid/exe 2>/dev/null | awk '{print $NF}')
        cmd_line=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')
        detected_service=""; if [ "$ppid" = "1" ]; then detected_service=$(find_service_file "$pid"); fi

        target_ip=""
        if has_cmd netstat; then target_ip=$(netstat -antp 2>/dev/null | grep "$pid/" | awk '{print $5}' | cut -d: -f1 | grep -v "0.0.0.0" | grep -v "127.0.0.1" | sort -u | head -n 1)
        elif has_cmd ss; then target_ip=$(ss -antp 2>/dev/null | grep "pid=$pid," | awk '{print $5}' | cut -d: -f1 | grep -v "127.0.0.1" | head -n 1); fi

        # 获取 IP 情报
        ip_info=""
        if [ -n "$target_ip" ]; then
            ip_info=$(get_ip_info "$target_ip")
        fi

        is_suspicious=0
        reason=""
        if [ -n "$cpu_usage" ] && [[ "$cpu_usage" =~ ^[0-9]+(\.[0-9]+)?$ ]] && awk "BEGIN {exit !($cpu_usage > $CPU_THRESHOLD)}"; then is_suspicious=1; reason="${reason}[High CPU] "; fi
        if echo "$proc_name $cmd_line" | grep -iqE "$MALWARE_KEYWORDS"; then is_suspicious=1; reason="${reason}[Keyword] "; fi
        if [ -n "$target_ip" ]; then is_suspicious=1; reason="${reason}[Network] "; fi
        if [[ "$exe_path" == /tmp* ]] || [[ "$exe_path" == /root/.* ]] || [[ "$exe_path" == /dev/shm* ]]; then is_suspicious=1; reason="${reason}[Path] "; fi

        if [ "$is_suspicious" -eq 0 ]; then continue; fi

        echo "------------------------------------------------------------"
        echo -e "${RED}► PID: $pid${NC} | Name: ${CYAN}$proc_name${NC} | CPU: ${RED}$cpu_usage%${NC}"
        echo -e "  Reason: ${YELLOW}$reason${NC}"
        echo -e "  Path  : $exe_path"
        echo -e "  Cmd   : ${cmd_line:0:100}..."

        if [ -n "$target_ip" ]; then echo -e "  Net   : ${RED}Connected to: $target_ip${NC} -> $ip_info"; fi
        if [ -n "$detected_service" ]; then echo -e "${RED}[!] LINKED SERVICE: $detected_service${NC}"; fi

        ask "Is this MALICIOUS? Kill & Delete? (y/Enter to skip): " confirm_auto
        if [[ "$confirm_auto" =~ ^[yY] ]]; then
            if [ -n "$target_ip" ] && has_cmd iptables; then
                ask "${RED}Block IP $target_ip in iptables? (y/n): ${NC}" block_ip
                if [[ "$block_ip" =~ ^[yY] ]]; then
                    if iptables -I OUTPUT -d "$target_ip" -j DROP 2>/dev/null && iptables -I INPUT -s "$target_ip" -j DROP 2>/dev/null; then
                        log "${GREEN}[✔] IP $target_ip blocked.${NC}"
                    else
                        log "${RED}[X] Failed to block IP $target_ip${NC}"
                    fi
                fi
            fi
            log "${RED}KILLING PID $pid...${NC}"
            if [ -n "$detected_service" ]; then
                systemctl stop "$(basename "$detected_service")" 2>/dev/null || true
                systemctl disable "$(basename "$detected_service")" 2>/dev/null || true
            fi
            if kill -9 "$pid" 2>/dev/null; then
                sleep 1
                if [ -n "$exe_path" ]; then quarantine_and_remove "$exe_path"; fi
                if [ -n "$detected_service" ] && [ -f "$detected_service" ]; then
                    ask "Also delete service file $detected_service ? (y/n): " c_svc
                    [[ "$c_svc" =~ ^[yY] ]] && quarantine_and_remove "$detected_service"
                fi
            else
                log "${RED}[X] Failed to kill PID $pid${NC}"
            fi
        fi
    done
}

# --- 2. 系统完整性 ---
scan_integrity() {
    header "2. System Integrity & Shell Audit"
    
    # 2.1 Hosts
    log "Checking /etc/hosts..."
    if grep -iE "virustotal|clamav|kaspersky|symantec" /etc/hosts >/dev/null 2>&1; then
        echo -e "${RED}[!!!] Security domains blocked in /etc/hosts!${NC}"
        grep -iE "virustotal|clamav|kaspersky|symantec" /etc/hosts
        ask "Fix /etc/hosts? (y/n): " fix_hosts
        if [[ "$fix_hosts" =~ ^[yY] ]]; then
            if cp /etc/hosts /etc/hosts.bak; then
                sed -i '/virustotal/d' /etc/hosts
                sed -i '/clamav/d' /etc/hosts
                log "${GREEN}[✔] /etc/hosts cleaned.${NC}"
            else
                log "${RED}[X] Failed to backup /etc/hosts${NC}"
            fi
        fi
    else
        log "${GREEN}[OK] /etc/hosts looks clean.${NC}"
    fi

    # 2.2 Shell Configs
    echo ""
    log "${CYAN}[*] Scanning Shell Configs (All Users) for suspicious commands...${NC}"
    SUSPICIOUS_CMD_REGEX="curl |wget |base64 |bash -i|nc |python |perl "
    SHELL_FILES=".bashrc .bash_profile .profile .zshrc .bash_login"
    
    for global_file in /etc/profile /etc/bash.bashrc /etc/zsh/zshrc; do
        if [ -f "$global_file" ] && grep -Eq "$SUSPICIOUS_CMD_REGEX" "$global_file"; then
            echo -e "${RED}[!!!] Suspicious command found in GLOBAL config: $global_file${NC}"
            grep -E --color=always "$SUSPICIOUS_CMD_REGEX" "$global_file"
            ask "${RED}Edit global config? (y/n): ${NC}" edit_global
            if [[ "$edit_global" =~ ^[yY] ]]; then
                ${EDITOR:-vi} "$global_file" < /dev/tty || log "${RED}[X] Failed to edit $global_file${NC}"
            fi
        fi
    done

    for home_dir in /root /home/*; do
        if [ -d "$home_dir" ]; then
            for shell_file in $SHELL_FILES; do
                target="$home_dir/$shell_file"
                if [ -f "$target" ] && grep -Eq "$SUSPICIOUS_CMD_REGEX" "$target"; then
                    echo -e "${RED}[!!!] Suspicious command in $target:${NC}"
                    grep -E --color=always "$SUSPICIOUS_CMD_REGEX" "$target" | head -n 5
                    ask "${RED}Edit/Clean this file? (y/n): ${NC}" edit_opt
                    if [[ "$edit_opt" =~ ^[yY] ]]; then
                        ${EDITOR:-vi} "$target" < /dev/tty || log "${RED}[X] Failed to edit $target${NC}"
                    fi
                fi
            done
        fi
    done
    log "${GREEN}[OK] Shell config scan completed.${NC}"
}

# --- 3. Docker ---
scan_docker() {
    header "3. Docker Container Check"
    if has_cmd docker && systemctl is-active --quiet docker 2>/dev/null; then
        log "${YELLOW}[+] Docker Running. Top CPU Containers:${NC}"
        docker_list=()
        while IFS= read -r line; do
            [ -n "$line" ] && docker_list+=("$line")
        done < <(docker stats --no-stream --format "{{.ID}} | {{.Name}} | CPU: {{.CPUPerc}}" 2>/dev/null | head -n 6)

        if [ ${#docker_list[@]} -eq 0 ]; then
            log "No containers found."
        else
            cnt=1; for c in "${docker_list[@]}"; do echo -e "[$cnt] $c"; ((cnt++)); done

            while true; do
                echo ""; ask "Select Number to INSPECT (Enter to continue): " choice
                if [ -z "$choice" ]; then break; fi
                if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#docker_list[@]}" ]; then
                    index=$((choice-1)); cid=$(echo "${docker_list[$index]}" | awk '{print $1}')
                    echo -e "${BLUE}--- Inspecting Container $cid ---${NC}"
                    if docker inspect --format 'Image: {{.Config.Image}} Cmd: {{.Config.Cmd}}' "$cid" 2>/dev/null; then
                        ask "${RED}Confirm STOP & REMOVE? (y/n): ${NC}" confirm
                        if [[ "$confirm" =~ ^[yY] ]]; then
                            if docker stop "$cid" 2>/dev/null && docker rm "$cid" 2>/dev/null; then
                                log "${GREEN}[✔] Container removed.${NC}"
                                ask "Also remove image? (y/n): " rmi
                                if [[ "$rmi" =~ ^[yY] ]]; then
                                    img=$(docker inspect --format='{{.Image}}' "$cid" 2>/dev/null)
                                    [ -n "$img" ] && docker rmi "$img" 2>/dev/null || true
                                fi
                            else
                                log "${RED}[X] Failed to remove container${NC}"
                            fi
                        fi
                    else
                        echo "Container not found."
                    fi
                else echo "Invalid selection."; fi
            done
        fi
    else
        log "Docker not found or inactive."
    fi
}

# --- 4. PM2 ---
scan_pm2() {
    header "4. PM2 Process Check"
    if has_cmd pm2; then
        log "${YELLOW}[+] PM2 detected! Gathering list...${NC}"
        pm2_list=()
        json_output=$(pm2 jlist 2>/dev/null); if [ -z "$json_output" ]; then json_output="[]"; fi
        clean_list=$(echo "$json_output" | sed 's/},{/\n/g' | tr -d '[]')

        if [ -n "$clean_list" ] && [ "$clean_list" != "" ]; then
            while IFS= read -r line; do
                if [ -z "$line" ]; then continue; fi
                id=$(echo "$line" | grep -o '"pm_id": *[0-9]*' | awk -F: '{print $2}' | tr -d ' ,')
                name=$(echo "$line" | grep -o '"name": *"[^"]*"' | awk -F: '{print $2}' | tr -d '"')
                cwd=$(echo "$line" | grep -o '"pm_cwd": *"[^"]*"' | awk -F: '{print $2}' | tr -d '"')
                if [ -n "$id" ]; then
                    warning=""; if echo "$name" | grep -iE "$MALWARE_KEYWORDS" >/dev/null 2>&1; then warning="${RED}[MALICIOUS?]${NC}"; fi
                    pm2_list+=("ID:$id | Name:$name | Dir:$cwd $warning")
                fi
            done <<< "$clean_list"
        fi

        if [ ${#pm2_list[@]} -eq 0 ]; then
            log "No running PM2 processes found."
        else
            cnt=1; for item in "${pm2_list[@]}"; do echo -e "[$cnt] $item"; ((cnt++)); done

            while true; do
                echo ""; ask "Select Number to INSPECT (Enter to continue): " choice
                if [ -z "$choice" ]; then break; fi
                if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#pm2_list[@]}" ]; then
                    index=$((choice-1)); target_id=$(echo "${pm2_list[$index]}" | awk -F'|' '{print $1}' | cut -d: -f2 | tr -d ' ')
                    echo -e "${BLUE}--- Inspecting PM2 ID $target_id ---${NC}"
                    if pm2 show "$target_id" 2>/dev/null | grep -E "script path|args|error log|out log|exec mode|created at"; then
                        echo -e "${BLUE}------------------------------------${NC}"
                        ask "${RED}Confirm DELETE PM2 ID $target_id? (y/n): ${NC}" confirm
                        if [[ "$confirm" =~ ^[yY] ]]; then
                            if pm2 stop "$target_id" 2>/dev/null && pm2 delete "$target_id" 2>/dev/null && pm2 save 2>/dev/null; then
                                log "${GREEN}[✔] PM2 process $target_id deleted.${NC}"
                            else
                                log "${RED}[X] Failed to delete PM2 process $target_id${NC}"
                            fi
                        fi
                    else
                        log "${RED}[X] Failed to show PM2 process $target_id${NC}"
                    fi
                else echo "Invalid selection."; fi
            done
        fi
    else
        log "PM2 not found."
    fi
}

# --- 5. 持久化 ---
scan_persistence() {
    header "5. Persistence Check (Crontab & Systemd)"
    
    log "Scanning ALL Crontab paths..."
    CRON_PATHS="/var/spool/cron/root /var/spool/cron/crontabs/root /etc/crontab /etc/cron.d/*"
    cron_files=()
    for path in $CRON_PATHS; do
        if [ -s "$path" ]; then cron_files+=("$path"); fi
    done

    if [ ${#cron_files[@]} -eq 0 ]; then
        log "${GREEN}[OK] No active crontabs found.${NC}"
    else
        echo -e "${BLUE}--- Found Crontab Files ---${NC}"
        cnt=1; for f in "${cron_files[@]}"; do
            warning=""; if grep -Eq "curl|wget|base64|sh |bash |\.\." "$f" 2>/dev/null; then warning="${RED}[SUSPICIOUS]${NC}"; fi
            echo -e "[$cnt] $f $warning"; ((cnt++))
        done

        while true; do
            echo ""; ask "Select Number to INSPECT CONTENT (Enter to continue): " choice
            if [ -z "$choice" ]; then break; fi
            if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#cron_files[@]}" ]; then
                index=$((choice-1)); target_cron="${cron_files[$index]}"
                if [ ! -f "$target_cron" ]; then echo "File not found."; continue; fi
                echo -e "${BLUE}================ FILE CONTENT: $target_cron =================${NC}"
                cat "$target_cron"
                echo -e "${BLUE}============================================================${NC}"
                ask "${RED}Clear this file (Empty it)? (y/n): ${NC}" confirm
                if [[ "$confirm" =~ ^[yY] ]]; then
                    if cp "$target_cron" "${target_cron}.bak"; then
                        > "$target_cron"
                        log "${GREEN}[✔] File cleared: $target_cron${NC}"
                    else
                        log "${RED}[X] Failed to backup $target_cron${NC}"
                    fi
                fi
            else echo "Invalid selection."; fi
        done
    fi
    
    log "Checking Systemd paths (Newest First)..."
    SEARCH_PATHS="/etc/systemd/system /usr/lib/systemd/system /etc/systemd/user /root/.config/systemd/user"
    service_files=()
    while IFS= read -r line; do
        if [ -n "$line" ]; then service_files+=("$line"); fi
    done < <(find $SEARCH_PATHS -name "*.service" -type f -printf "%T@ %p\n" 2>/dev/null | sort -rn | head -n 20 | cut -d' ' -f2-)

    if [ ${#service_files[@]} -eq 0 ]; then
        log "No service files found (unlikely)."
    else
        cnt=1; for svc in "${service_files[@]}"; do
            if has_cmd date; then mod_time=$(date -r "$svc" "+%Y-%m-%d %H:%M" 2>/dev/null); else mod_time="[Time Unknown]"; fi
            echo "[$cnt] $mod_time $svc"; ((cnt++))
        done

        while true; do
            echo ""; ask "Select Number to INSPECT CONTENT (Enter to continue): " choice
            if [ -z "$choice" ]; then break; fi
            if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#service_files[@]}" ]; then
                index=$((choice-1)); target_svc="${service_files[$index]}"
                if [ ! -f "$target_svc" ]; then echo "File not found."; continue; fi
                echo -e "${BLUE}================ FILE CONTENT: $target_svc =================${NC}"
                head -n 50 "$target_svc"
                echo -e "${BLUE}============================================================${NC}"
                if grep -Eq "bash|sh |curl|wget|base64" "$target_svc" 2>/dev/null; then echo -e "${RED}[!!!] DANGER: Suspicious commands detected!${NC}"; fi
                ask "${RED}Confirm QUARANTINE & DELETE? (y/n): ${NC}" confirm
                if [[ "$confirm" =~ ^[yY] ]]; then
                    svc_name=$(basename "$target_svc")
                    systemctl stop "$svc_name" 2>/dev/null || true
                    systemctl disable "$svc_name" 2>/dev/null || true
                    quarantine_and_remove "$target_svc"
                    systemctl daemon-reload 2>/dev/null || true
                fi
            else echo "Invalid selection."; fi
        done
    fi
}

# --- 6. Rootkit (新增：账户审计) ---
scan_rootkit() {
    header "6. Advanced Rootkit & Account Audit"
    
    # [新增] 账户审计
    log "${CYAN}[*] Auditing System Accounts (Looking for login shells)...${NC}"
    echo -e "User       | UID  | Shell"
    echo -e "-----------|------|-----------------"
    awk -F: '($7 ~ /(bash|sh|zsh)$/) {printf "%-10s | %-4s | %s\n", $1, $3, $7}' /etc/passwd

    echo ""
    suspicious_users=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd)
    if [ -n "$suspicious_users" ]; then
        echo -e "${RED}[!!!] DANGER: Backdoor user (UID 0) found: $suspicious_users${NC}"
        ask "Delete user '$suspicious_users'? (y/n): " c
        if [[ "$c" =~ ^[yY] ]]; then
            if userdel -f "$suspicious_users" 2>/dev/null; then
                log "${GREEN}[✔] User $suspicious_users deleted.${NC}"
            else
                log "${RED}[X] Failed to delete user $suspicious_users${NC}"
            fi
        fi
    else
        log "${GREEN}[OK] No extra UID 0 users found.${NC}"
    fi

    echo ""
    log "${CYAN}[*] Kernel Integrity & Modules:${NC}"
    taint_val=$(cat /proc/sys/kernel/tainted 2>/dev/null)
    if [ "$taint_val" != "0" ]; then
         echo -e "${RED}[!] WARNING: Kernel is TAINTED (Value: $taint_val).${NC}"
    else
         echo -e "${GREEN}[OK] Kernel is not tainted.${NC}"
    fi
    
    echo -e "${YELLOW}Top 10 Loaded Modules:${NC}"
    lsmod | head -n 11
    
    log "${CYAN}[*] Checking LD_PRELOAD:${NC}"
    if [ -s /etc/ld.so.preload ]; then
         echo -e "${RED}[!!!] CRITICAL: /etc/ld.so.preload found!${NC}"
         cat /etc/ld.so.preload
         ask "Delete this file? (y/n): " rm_preload
         [[ "$rm_preload" =~ ^[yY] ]] && quarantine_and_remove "/etc/ld.so.preload"
    else
         echo -e "${GREEN}[OK] No global LD_PRELOAD found.${NC}"
    fi

    log "${CYAN}[*] Checking Promiscuous Mode (Sniffers):${NC}"
    promisc_iface=$(ip link 2>/dev/null | grep "PROMISC")
    if [ ! -z "$promisc_iface" ]; then
         echo -e "${RED}[!] WARNING: Interface in PROMISC mode found:${NC}"
         echo "$promisc_iface"
    else
         echo -e "${GREEN}[OK] No interfaces in promiscuous mode.${NC}"
    fi

    log "Scanning extended suspicious directories for hidden items..."
    SUSPICIOUS_HIDDEN_DIRS="/tmp /var/tmp /var/run /var/lock /run /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /boot /etc"
    SHM_DIR="/dev/shm"

    hidden_items=()
    for dir in $SUSPICIOUS_HIDDEN_DIRS; do
        if [ -d "$dir" ]; then
            while IFS= read -r item; do
                base=$(basename "$item")
                if [ "$base" != "." ] && [ "$base" != ".." ] && [ ! -z "$item" ]; then 
                    hidden_items+=("$item") 
                fi
            done < <(find "$dir" -maxdepth 1 -name ".*" 2>/dev/null)
        fi
    done

    if [ -d "$SHM_DIR" ]; then
        while IFS= read -r item; do
             if [ ! -z "$item" ]; then hidden_items+=("$item"); fi
        done < <(find "$SHM_DIR" -maxdepth 1 -type f 2>/dev/null)
    fi
    
    if [ ${#hidden_items[@]} -eq 0 ]; then
        log "No suspicious hidden items found."
    else
        cnt=1; for item in "${hidden_items[@]}"; do
            info="File"; if [ -d "$item" ]; then info="Dir"; fi; if [ -x "$item" ]; then info="${RED}Exec${NC}"; fi
            echo -e "[$cnt] [$info] $item"; ((cnt++))
        done

        while true; do
            echo ""; ask "Select Number to INSPECT (Enter to continue): " choice
            if [ -z "$choice" ]; then break; fi
            if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#hidden_items[@]}" ]; then
                index=$((choice-1)); target_item="${hidden_items[$index]}"
                if [ ! -e "$target_item" ]; then echo "Item not found."; continue; fi

                echo -e "${BLUE}--- Inspecting: $target_item ---${NC}"

                if [ -d "$target_item" ]; then
                    echo -e "${YELLOW}Recursive Listing (Depth 3):${NC}"
                    find "$target_item" -maxdepth 3 -ls 2>/dev/null || true
                else
                    ls -alh "$target_item" 2>/dev/null || true
                    echo -e "${YELLOW}Type:${NC} $(file -b "$target_item" 2>/dev/null)"
                    if file "$target_item" 2>/dev/null | grep -q "text"; then
                        echo -e "${YELLOW}Content Preview:${NC}"
                        head -n 20 "$target_item" 2>/dev/null || true
                    fi
                fi

                echo -e "${BLUE}--------------------------------${NC}"
                ask "${RED}Confirm QUARANTINE & DELETE? (y/n): ${NC}" confirm
                if [[ "$confirm" =~ ^[yY] ]]; then
                    quarantine_and_remove "$target_item"
                fi
            else echo "Invalid selection."; fi
        done
    fi
}

# --- 7. SSH (新增：全用户遍历) ---
scan_ssh() {
    header "7. SSH Keys Check (All Users)"
    
    # 扫描 /root 和 /home/* 下的 .ssh/authorized_keys
    for home_dir in /root /home/*; do
        if [ -d "$home_dir" ]; then
            ssh_dir="$home_dir/.ssh"
            auth_file="$ssh_dir/authorized_keys"

            if [ -f "$auth_file" ]; then
                echo -e "${BLUE}>>> Found SSH Keys in: ${YELLOW}$auth_file${NC}"
                ls -l "$auth_file" 2>/dev/null || true
                echo "---------------------------------------------------"
                cat "$auth_file" 2>/dev/null || true
                echo "---------------------------------------------------"

                ask "${RED}Edit this file? (y/n): ${NC}" c
                if [[ "$c" =~ ^[yY] ]]; then
                    if cp "$auth_file" "${auth_file}.bak"; then
                        ${EDITOR:-vi} "$auth_file" < /dev/tty || log "${RED}[X] Failed to edit $auth_file${NC}"
                        log "Updated: $auth_file"
                    else
                        log "${RED}[X] Failed to backup $auth_file${NC}"
                    fi
                fi
                echo ""
            fi
        fi
    done
}
check_shell_users() {
    echo -e "\n[+] 正在检测所有 Shell 为 bash 或 sh 的账户 (可能包含后门或服务账户)..."
    echo "-------------------------------------------------------------------"

    # 使用 awk 匹配第7列（Shell路径），只要以 bash 或 sh 结尾即打印整行
    # 这将覆盖 /bin/bash, /bin/sh, /usr/bin/bash, /bin/dash 等情况
    awk -F: '$7 ~ /(bash|sh)$/ {print $0}' /etc/passwd

    echo "-------------------------------------------------------------------"
}

# --- 8. 网络连接全景扫描 ---
scan_network_connections() {
    header "8. Network Connections Panorama"

    log "${CYAN}[*] Scanning all ESTABLISHED connections for IP intelligence...${NC}"

    # 解析 /proc/net/tcp 和 /proc/net/tcp6
    local tcp_file="/proc/net/tcp"
    local tcp6_file="/proc/net/tcp6"
    local connections=()

    # 处理 IPv4 连接
    if [ -f "$tcp_file" ]; then
        while IFS= read -r line; do
            # 跳过头行
            if [[ "$line" =~ ^sl ]]; then continue; fi

            # 解析 remote_address（十六进制）
            local remote_addr=$(echo "$line" | awk '{print $3}' | cut -d: -f1)
            local remote_port=$(echo "$line" | awk '{print $3}' | cut -d: -f2)
            local state=$(echo "$line" | awk '{print $4}')

            # 仅关注 ESTABLISHED (01)
            if [ "$state" != "01" ]; then continue; fi

            # 十六进制转 IP（小端序）
            local ip=$(printf "%d.%d.%d.%d" \
                0x${remote_addr:6:2} \
                0x${remote_addr:4:2} \
                0x${remote_addr:2:2} \
                0x${remote_addr:0:2} 2>/dev/null)

            if [ -n "$ip" ] && ! [[ "$ip" =~ ^0\. ]]; then
                connections+=("$ip")
            fi
        done < "$tcp_file"
    fi

    # 处理 IPv6 连接（简化处理）
    if [ -f "$tcp6_file" ]; then
        while IFS= read -r line; do
            if [[ "$line" =~ ^sl ]]; then continue; fi
            local state=$(echo "$line" | awk '{print $4}')
            if [ "$state" != "01" ]; then continue; fi
            # IPv6 处理较复杂，这里仅记录存在
            connections+=("[IPv6]")
        done < "$tcp6_file"
    fi

    if [ ${#connections[@]} -eq 0 ]; then
        log "${GREEN}[OK] No external ESTABLISHED connections found.${NC}"
        return
    fi

    # 去重并查询情报
    local unique_ips=$(printf '%s\n' "${connections[@]}" | sort -u)
    local cnt=1

    echo -e "${BLUE}--- Network Connections with IP Intelligence ---${NC}"
    while IFS= read -r ip; do
        if [ -z "$ip" ]; then continue; fi

        if [[ "$ip" == "[IPv6]" ]]; then
            echo "[$cnt] [IPv6] (IPv6 connections detected)"
            ((cnt++))
            continue
        fi

        local ip_info=$(get_ip_info "$ip")
        echo "[$cnt] $ip -> $ip_info"
        ((cnt++))
    done <<< "$unique_ips"

    echo -e "${BLUE}-------------------------------------------${NC}"
}

# --- 9. DNS 服务器审计 ---
scan_dns_servers() {
    header "9. DNS Servers Audit"

    log "${CYAN}[*] Checking DNS servers in /etc/resolv.conf...${NC}"

    if [ ! -f /etc/resolv.conf ]; then
        log "${CYAN}[-] /etc/resolv.conf not found.${NC}"
        return
    fi

    local dns_servers=$(grep "^nameserver" /etc/resolv.conf | awk '{print $2}')

    if [ -z "$dns_servers" ]; then
        log "${GREEN}[OK] No DNS servers configured.${NC}"
        return
    fi

    echo -e "${BLUE}--- DNS Servers with IP Intelligence ---${NC}"
    local cnt=1
    while IFS= read -r dns_ip; do
        if [ -z "$dns_ip" ]; then continue; fi

        local ip_info=$(get_ip_info "$dns_ip")
        echo "[$cnt] $dns_ip -> $ip_info"
        ((cnt++))
    done <<< "$dns_servers"
    echo -e "${BLUE}--------------------------------------${NC}"
}

# --- 10. Service 文件网络连接审计 ---
scan_service_network() {
    header "10. Service Files Network Audit"

    log "${CYAN}[*] Scanning service files for hardcoded IP/domain connections...${NC}"

    local SEARCH_PATHS="/etc/systemd/system /usr/lib/systemd/system"
    local service_files=()

    while IFS= read -r svc; do
        if [ -n "$svc" ]; then service_files+=("$svc"); fi
    done < <(find $SEARCH_PATHS -name "*.service" -type f 2>/dev/null)

    if [ ${#service_files[@]} -eq 0 ]; then
        log "No service files found."
        return
    fi

    local suspicious_count=0
    echo -e "${BLUE}--- Service Files with Network Connections ---${NC}"

    for svc in "${service_files[@]}"; do
        # 提取 ExecStart 中的 IP 地址
        local ips=$(grep -oE "ExecStart=.*" "$svc" | grep -oE "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" 2>/dev/null)

        if [ -n "$ips" ]; then
            echo -e "${RED}[!!!] $(basename "$svc") contains hardcoded IPs:${NC}"
            while IFS= read -r ip; do
                if [ -z "$ip" ]; then continue; fi
                local ip_info=$(get_ip_info "$ip")
                echo "      $ip -> $ip_info"
                ((suspicious_count++))
            done <<< "$ips"
        fi
    done

    if [ $suspicious_count -eq 0 ]; then
        log "${GREEN}[OK] No suspicious IPs found in service files.${NC}"
    fi
    echo -e "${BLUE}-------------------------------------------${NC}"
}

# --- 11. /etc/hosts 文件 IP 情报查询 ---
scan_hosts_intelligence() {
    header "11. /etc/hosts IP Intelligence"

    log "${CYAN}[*] Checking /etc/hosts for suspicious entries...${NC}"

    if [ ! -f /etc/hosts ]; then
        log "${CYAN}[-] /etc/hosts not found.${NC}"
        return
    fi

    # 提取所有非注释、非本地的 IP
    local hosts_ips=$(grep -v "^#" /etc/hosts | grep -v "^$" | awk '{print $1}' | grep -v "^127\." | grep -v "^::1" | sort -u)

    if [ -z "$hosts_ips" ]; then
        log "${GREEN}[OK] No external IPs in /etc/hosts.${NC}"
        return
    fi

    echo -e "${BLUE}--- /etc/hosts External IPs with Intelligence ---${NC}"
    local cnt=1
    while IFS= read -r ip; do
        if [ -z "$ip" ]; then continue; fi

        local ip_info=$(get_ip_info "$ip")
        echo "[$cnt] $ip -> $ip_info"
        ((cnt++))
    done <<< "$hosts_ips"
    echo -e "${BLUE}----------------------------------------------${NC}"
}

# --- 执行主流程 ---
check_root
scan_overview
scan_process
scan_integrity
scan_docker
scan_pm2
scan_persistence
scan_rootkit
scan_ssh
scan_network_connections
scan_dns_servers
scan_service_network
scan_hosts_intelligence
check_shell_users
cleanup
