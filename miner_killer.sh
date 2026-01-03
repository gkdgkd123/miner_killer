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
BACKUP_DIR="/tmp/malware_quarantine_$(date +%Y%m%d_%H%M%S)"
LOCK_FILE="/tmp/miner_killer.lock"

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
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') $msg" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE"
}

header() {
    echo -e "${BLUE}============================================================${NC}"
    log "${YELLOW}$1${NC}"
    echo -e "${BLUE}============================================================${NC}"
}

ask() {
    local prompt="$1"
    local var_name="$2"
    eval "$var_name=''"
    echo -ne "${YELLOW}${prompt}${NC}" > /dev/tty
    read -r "$var_name" < /dev/tty
}

has_cmd() { command -v "$1" >/dev/null 2>&1; }

check_root() {
    if [ "$EUID" -ne 0 ]; then echo -e "${RED}Error: Must run as root.${NC}"; exit 1; fi
}

quarantine_and_remove() {
    local target="$1"
    target=$(echo "$target" | sed 's/ (deleted)//' | awk '{print $1}')
    if [ -z "$target" ]; then return; fi
    if [ -e "$target" ] || [ -L "$target" ]; then
        if has_cmd chattr; then chattr -R -i -a "$target" 2>/dev/null; fi
        chmod -R -x "$target" 2>/dev/null
        if [ -f "$target" ] || [ -d "$target" ]; then
            safe_name=$(echo "$target" | sed 's/\//_/g')
            cp -rp "$target" "$BACKUP_DIR/$safe_name" 2>/dev/null
            log "[Safe] Quarantined to: $BACKUP_DIR/$safe_name"
        fi
        rm -rf "$target"
        if [ $? -eq 0 ]; then log "${GREEN}[✔] Deleted: $target${NC}"; else log "${RED}[X] Failed to delete: $target${NC}"; fi
    elif [ -d "$target" ]; then
        rm -rf "$target"
        log "${GREEN}[✔] Deleted directory: $target${NC}"
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
    log "Scanning processes (Logic: CPU>10% OR Network OR Keywords)..."
    
    target_pids=$(ps -eo pid,%cpu,comm,cmd --sort=-%cpu | head -n 10 | awk 'NR>1 {print $1}')
    keyword_pids=$(ps -ef | grep -iE "$MALWARE_KEYWORDS" | grep -v grep | awk '{print $2}' | head -n 5)
    
    net_pids=""
    if has_cmd netstat; then
        net_pids=$(netstat -antp 2>/dev/null | grep 'ESTABLISHED' | grep -v '127.0.0.1' | grep -v 'sshd' | awk '{print $7}' | cut -d/ -f1)
    elif has_cmd ss; then
        net_pids=$(ss -antp 2>/dev/null | grep 'ESTABLISHED' | grep -v '127.0.0.1' | grep -v 'sshd' | awk '{print $6}' | cut -d, -f2)
    fi
    
    all_pids=$(echo -e "$target_pids\n$keyword_pids\n$net_pids" | tr ' ' '\n' | sort -u | grep -v '^$')

    for pid in $all_pids; do
        if [[ ! "$pid" =~ ^[0-9]+$ ]] || [ ! -d "/proc/$pid" ]; then continue; fi
        ppid=$(ps -o ppid= -p $pid 2>/dev/null | tr -d ' ')
        if [ "$ppid" == "2" ]; then continue; fi 

        proc_name=$(ps -p "$pid" -o comm=)
        if echo "$proc_name" | grep -iqE "$WHITELIST"; then continue; fi
        
        cpu_usage=$(ps -p "$pid" -o %cpu=)
        exe_path=""; if has_cmd readlink; then exe_path=$(readlink -f /proc/$pid/exe 2>/dev/null); fi
        [ -z "$exe_path" ] && exe_path=$(ls -l /proc/$pid/exe 2>/dev/null | awk '{print $NF}')
        cmd_line=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')
        detected_service=""; if [ "$ppid" == "1" ]; then detected_service=$(find_service_file "$pid"); fi

        target_ip=""
        if has_cmd netstat; then target_ip=$(netstat -antp 2>/dev/null | grep "$pid/" | awk '{print $5}' | cut -d: -f1 | grep -v "0.0.0.0" | grep -v "127.0.0.1" | sort -u | head -n 1)
        elif has_cmd ss; then target_ip=$(ss -antp 2>/dev/null | grep "pid=$pid," | awk '{print $5}' | cut -d: -f1 | grep -v "127.0.0.1" | head -n 1); fi

        is_suspicious=0
        reason=""
        if (( $(echo "$cpu_usage > 10.0" | bc -l 2>/dev/null) )); then is_suspicious=1; reason="${reason}[High CPU] "; fi
        if echo "$proc_name $cmd_line" | grep -iqE "$MALWARE_KEYWORDS"; then is_suspicious=1; reason="${reason}[Keyword] "; fi
        if [ ! -z "$target_ip" ]; then is_suspicious=1; reason="${reason}[Network] "; fi
        if [[ "$exe_path" == /tmp* ]] || [[ "$exe_path" == /root/.* ]] || [[ "$exe_path" == /dev/shm* ]]; then is_suspicious=1; reason="${reason}[Path] "; fi
        
        if [ "$is_suspicious" -eq 0 ]; then continue; fi

        echo "------------------------------------------------------------"
        echo -e "${RED}► PID: $pid${NC} | Name: ${CYAN}$proc_name${NC} | CPU: ${RED}$cpu_usage%${NC}"
        echo -e "  Reason: ${YELLOW}$reason${NC}"
        echo -e "  Path  : $exe_path"
        echo -e "  Cmd   : ${cmd_line:0:100}..." 
        
        if [ ! -z "$target_ip" ]; then echo -e "  Net   : ${RED}Connected to: $target_ip${NC}"; fi
        if [ ! -z "$detected_service" ]; then echo -e "${RED}[!] LINKED SERVICE: $detected_service${NC}"; fi

        ask "Is this MALICIOUS? Kill & Delete? (y/Enter to skip): " confirm_auto
        if [[ "$confirm_auto" =~ ^[yY] ]]; then
            if [ ! -z "$target_ip" ] && has_cmd iptables; then
                ask "${RED}Block IP $target_ip in iptables? (y/n): ${NC}" block_ip
                if [[ "$block_ip" =~ ^[yY] ]]; then
                    iptables -I OUTPUT -d "$target_ip" -j DROP
                    iptables -I INPUT -s "$target_ip" -j DROP
                    log "${GREEN}[✔] IP $target_ip blocked.${NC}"
                fi
            fi
            log "${RED}KILLING PID $pid...${NC}"
            if [ ! -z "$detected_service" ]; then systemctl stop "$(basename "$detected_service")" 2>/dev/null; systemctl disable "$(basename "$detected_service")" 2>/dev/null; fi
            kill -9 "$pid" 2>/dev/null; sleep 1
            if [ ! -z "$exe_path" ]; then quarantine_and_remove "$exe_path"; fi
            if [ ! -z "$detected_service" ] && [ -f "$detected_service" ]; then
                ask "Also delete service file $detected_service ? (y/n): " c_svc
                [[ "$c_svc" =~ ^[yY] ]] && quarantine_and_remove "$detected_service"
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
            cp /etc/hosts /etc/hosts.bak; sed -i '/virustotal/d' /etc/hosts; sed -i '/clamav/d' /etc/hosts; log "${GREEN}[✔] /etc/hosts cleaned.${NC}"
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
            [[ "$edit_global" =~ ^[yY] ]] && ${EDITOR:-vi} "$global_file" < /dev/tty
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
                    [[ "$edit_opt" =~ ^[yY] ]] && ${EDITOR:-vi} "$target" < /dev/tty
                fi
            done
        fi
    done
    log "${GREEN}[OK] Shell config scan completed.${NC}"
}

# --- 3. Docker ---
scan_docker() {
    header "3. Docker Container Check"
    if has_cmd docker && systemctl is-active --quiet docker; then
        log "${YELLOW}[+] Docker Running. Top CPU Containers:${NC}"
        docker_list=()
        while IFS= read -r line; do docker_list+=("$line"); done < <(docker stats --no-stream --format "{{.ID}} | {{.Name}} | CPU: {{.CPUPerc}}" | head -n 6)
        
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
                    docker inspect --format 'Image: {{.Config.Image}} Cmd: {{.Config.Cmd}}' "$cid" 2>/dev/null
                    if [ $? -ne 0 ]; then echo "Container not found."; continue; fi
                    ask "${RED}Confirm STOP & REMOVE? (y/n): ${NC}" confirm
                    if [[ "$confirm" =~ ^[yY] ]]; then
                        docker stop "$cid"; docker rm "$cid"; log "${GREEN}[✔] Container removed.${NC}"
                        ask "Also remove image? (y/n): " rmi
                        [[ "$rmi" =~ ^[yY] ]] && docker rmi "$(docker inspect --format='{{.Image}}' $cid)"
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
        
        if [ ! -z "$clean_list" ] && [ "$clean_list" != "" ]; then
            while IFS= read -r line; do
                if [ -z "$line" ]; then continue; fi
                id=$(echo $line | grep -o '"pm_id": *[0-9]*' | awk -F: '{print $2}' | tr -d ' ,')
                name=$(echo $line | grep -o '"name": *"[^"]*"' | awk -F: '{print $2}' | tr -d '"')
                cwd=$(echo $line | grep -o '"pm_cwd": *"[^"]*"' | awk -F: '{print $2}' | tr -d '"')
                if [ ! -z "$id" ]; then
                    warning=""; if echo "$name" | grep -iE "$MALWARE_KEYWORDS" >/dev/null; then warning="${RED}[MALICIOUS?]${NC}"; fi
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
                    pm2 show "$target_id" | grep -E "script path|args|error log|out log|exec mode|created at"
                    echo -e "${BLUE}------------------------------------${NC}"
                    ask "${RED}Confirm DELETE PM2 ID $target_id? (y/n): ${NC}" confirm
                    [[ "$confirm" =~ ^[yY] ]] && { pm2 stop "$target_id"; pm2 delete "$target_id"; pm2 save; log "${GREEN}[✔] PM2 process $target_id deleted.${NC}"; }
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
            warning=""; if grep -Eq "curl|wget|base64|sh |bash |\.\." "$f"; then warning="${RED}[SUSPICIOUS]${NC}"; fi
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
                if [[ "$confirm" =~ ^[yY] ]]; then cp "$target_cron" "${target_cron}.bak"; > "$target_cron"; log "${GREEN}[✔] File cleared: $target_cron${NC}"; fi
            else echo "Invalid selection."; fi
        done
    fi
    
    log "Checking Systemd paths (Newest First)..."
    SEARCH_PATHS="/etc/systemd/system /usr/lib/systemd/system /etc/systemd/user /root/.config/systemd/user"
    service_files=()
    while IFS= read -r line; do if [ ! -z "$line" ]; then service_files+=("$line"); fi; done < <(find $SEARCH_PATHS -name "*.service" -type f -printf "%T@ %p\n" 2>/dev/null | sort -rn | head -n 20 | cut -d' ' -f2-)

    if [ ${#service_files[@]} -eq 0 ]; then
        log "No service files found (unlikely)."
    else
        cnt=1; for svc in "${service_files[@]}"; do
            if has_cmd date; then mod_time=$(date -r "$svc" "+%Y-%m-%d %H:%M"); else mod_time="[Time Unknown]"; fi
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
                if grep -Eq "bash|sh |curl|wget|base64" "$target_svc"; then echo -e "${RED}[!!!] DANGER: Suspicious commands detected!${NC}"; fi
                ask "${RED}Confirm QUARANTINE & DELETE? (y/n): ${NC}" confirm
                if [[ "$confirm" =~ ^[yY] ]]; then
                    svc_name=$(basename "$target_svc")
                    systemctl stop "$svc_name" 2>/dev/null; systemctl disable "$svc_name" 2>/dev/null
                    quarantine_and_remove "$target_svc"; systemctl daemon-reload
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
    # 查找所有拥有登录 Shell (bash/sh/zsh) 的用户
    awk -F: '($7 ~ /(bash|sh|zsh)$/) {printf "%-10s | %-4s | %s\n", $1, $3, $7}' /etc/passwd
    
    echo ""
    suspicious_users=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd)
    if [ ! -z "$suspicious_users" ]; then
        echo -e "${RED}[!!!] DANGER: Backdoor user (UID 0) found: $suspicious_users${NC}"
        ask "Delete user '$suspicious_users'? (y/n): " c
        [[ "$c" =~ ^[yY] ]] && userdel -f "$suspicious_users"
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
                    find "$target_item" -maxdepth 3 -ls
                else
                    ls -alh "$target_item"
                    echo -e "${YELLOW}Type:${NC} $(file -b "$target_item")"
                    if file "$target_item" | grep -q "text"; then 
                        echo -e "${YELLOW}Content Preview:${NC}"
                        head -n 20 "$target_item"
                    fi
                fi
                
                echo -e "${BLUE}--------------------------------${NC}"
                ask "${RED}Confirm QUARANTINE & DELETE? (y/n): ${NC}" confirm
                [[ "$confirm" =~ ^[yY] ]] && quarantine_and_remove "$target_item"
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
                ls -l "$auth_file"
                echo "---------------------------------------------------"
                cat "$auth_file"
                echo "---------------------------------------------------"
                
                ask "${RED}Edit this file? (y/n): ${NC}" c
                if [[ "$c" =~ ^[yY] ]]; then
                    cp "$auth_file" "${auth_file}.bak"
                    ${EDITOR:-vi} "$auth_file" < /dev/tty
                    log "Updated: $auth_file"
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
check_shell_users
cleanup
