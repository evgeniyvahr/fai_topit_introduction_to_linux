#!/bin/bash
export PATH=$PATH:/usr/sbin

VERSION="v3"
LOG_FILE="PASSPORT/log/report.log"
TMP_DIR="PASSPORT/tmp"
OUTPUT_FILE="PASSPORT/inventory.txt"

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi
if [ -n "${1-}" ]; then
    OUTPUT_FILE="$1"
fi

usage() {
    cat <<EOF
Использование: $0 [-h] [OUTPUT_FILE]
Собирает паспорт системы и разделы аудита безопасности в OUTPUT_FILE.
  -h, --help      показать эту справку
  OUTPUT_FILE     путь к итоговому отчёту (по умолчанию PASSPORT/inventory.txt)
Требует прав root или пользователя из группы sudo.
EOF
}

die() {
    echo "ОШИБКА: $*" >$2
    exit 1
}

cleanup() {
    rm -rf "$TMP_DIR"
}

check_privileges() {
    if [ "$(id -u)" -eq 0 ]; then
        PRIV_MODE="root"
    elif id -nG | grep -qw -e sudo -e wheel && command -v sudo >/dev/null 2>&1; then
        PRIV_MODE="sudo"
        sudo -v 2>/dev/null || true
    else
        PRIV_MODE="none"
        die "Недостаточно прав..."
    fi
}

run_priv() {
    if [ "$PRIV_MODE" = "root" ]; then
        "$@"
    else
        sudo "$@"
    fi
}

check_tool() {
    local tool="$1" pkg="$2"
    if command -v "$tool" >/dev/null 2>&1; then
        return 0
    fi
    echo "Утилита '$tool' не найдена. Установите пакет: $pkg" >&2
    return 1
}

write_section() {
    local title="$1"
    echo "$title" >> "$OUTPUT_FILE"
    cat >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
}

log_run() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') format=$VERSION user=$(whoami) mode=$PRIV_MODE" >> "$LOG_FILE"
}

get_last_login() {
    local user="$1" out=""
    if command -v lastlog2 >/dev/null 2>&1; then
        out=$(lastlog2 -u "$user" 2>/dev/null | awk 'NR>1' | head -1)
    fi
    if [ -z "$out" ] && command -v lslogins >/dev/null 2>&1; then
        out=$(lslogins -u "$user" -o LAST-LOGIN --noheadings 2>/dev/null | head -1)
    fi
    if [ -z "$out" ] || printf '%s' "$out" | grep -qi 'never'; then
        echo "нет данных"
    else
        echo "$out"
    fi
}

is_explicit_param() {
    local name="$1"
    grep -riE "^[[:space:]]*${name}[[:space:]]" \
        /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null \
        | grep -qv '^[[:space:]]*#'
}

build_users_report() {
    if [ ! -s "$TMP_DIR/users_raw.tmp" ]; then
        echo "нет данных"; return
    fi
    printf "%-12s %-6s %-28s %-22s %s\n" "ИМЯ" "UID" "ГРУППЫ" "ПОСЛ.ВХОД" "СМЕНА ПАРОЛЯ"
    while IFS='|' read -r user uid groups lastlogin pwdchange; do
        printf "%-12s %-6s %-28s %-22s %s\n" "$user" "$uid" "$groups" "$lastlogin" "$pwdchange"
    done < "$TMP_DIR/users_raw.tmp"
}

build_sshd_report() {
    if [ ! -s "$TMP_DIR/sshd_raw.tmp" ]; then
        echo "нет данных"; return
    fi
    for p in permitrootlogin port logingracetime maxauthtries passwordauthentication pubkeyauthentication; do
        val=$(awk -v k="$p" '$1==k{print $2}' "$TMP_DIR/sshd_raw.tmp")
        if is_explicit_param "$p"; then src="явно в конфиге"; else src="по умолчанию"; fi
        printf "%-26s = %-12s (%s)\n" "$p" "${val:-?}" "$src"
    done
}

check_privileges
mkdir -p PASSPORT/log "$TMP_DIR"
trap cleanup EXIT INT TERM
: > "$OUTPUT_FILE"

write_section "===Режим запуска===" < <(echo "mode=$PRIV_MODE user=$(whoami) uid=$(id -u)")
log_run

{ date; hostname; } > "$TMP_DIR/host_info.tmp"
{ whoami; who; } > "$TMP_DIR/user_info.tmp"
{ pwd; ls; } > "$TMP_DIR/dir_info.tmp"
{ uname -r; uname -m; } > "$TMP_DIR/kernel_info.tmp"
cat /etc/os-release > "$TMP_DIR/os_info.tmp"
if check_tool lscpu cpu-utils; then LC_ALL=C lscpu > "$TMP_DIR/cpu_info.tmp"
else echo "lscpu недоступна" > "$TMP_DIR/cpu_info.tmp"; fi
free -h > "$TMP_DIR/memory_info.tmp"
if check_tool dmidecode dmidecode; then
    dmidecode -t baseboard > "$TMP_DIR/motherboard_info.tmp"
    dmidecode -t bios > "$TMP_DIR/bios_info.tmp"
else
    echo "dmidecode недоступна" > "$TMP_DIR/motherboard_info.tmp"
    echo "dmidecode недоступна" > "$TMP_DIR/bios_info.tmp"
fi
if check_tool lspci pciutils; then lspci > "$TMP_DIR/pci_info.tmp"
else echo "lspci недоступна" > "$TMP_DIR/pci_info.tmp"; fi

getent passwd | awk -F: '($3>=1000 || $3==0){print $1"|"$3}' > "$TMP_DIR/users_list.tmp"
: > "$TMP_DIR/users_raw.tmp"
while IFS='|' read -r user uid; do
    groups=$(id -nG "$user" 2>/dev/null)
    pwdchange=$(LC_ALL=C run_priv chage -l "$user" 2>/dev/null | grep "Last password change" | sed 's/.*: //')
    lastlogin=$(get_last_login "$user")
    echo "$user|$uid|$groups|$lastlogin|$pwdchange" >> "$TMP_DIR/users_raw.tmp"
done < "$TMP_DIR/users_list.tmp"

run_priv sshd -T > "$TMP_DIR/sshd_raw.tmp" 2>/dev/null

run_priv ps -eo pid,ppid,user,%mem,cmd --sort=-%mem > "$TMP_DIR/top5_raw.tmp" 2>/dev/null

run_priv awk -F: '$2==""{print $1}' /etc/shadow > "$TMP_DIR/shadow_empty.tmp" 2>/dev/null
awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd > "$TMP_DIR/uid0.tmp" 2>/dev/null

run_priv find /usr/bin /usr/sbin -perm -4000 > "$TMP_DIR/suid_raw.tmp" 2>/dev/null

write_section "===Информация о хосте===" < "$TMP_DIR/host_info.tmp"
write_section "===Информация о пользователе===" < "$TMP_DIR/user_info.tmp"
write_section "===Информация о каталоге===" < "$TMP_DIR/dir_info.tmp"
write_section "===Название и версия ядра, разрядность системы===" < "$TMP_DIR/kernel_info.tmp"
write_section "===Версия операционной системы===" < "$TMP_DIR/os_info.tmp"
{
    grep "Model name" "$TMP_DIR/cpu_info.tmp" | sed 's/Model name:\s*//'
    grep "CPU MHz" "$TMP_DIR/cpu_info.tmp" | head -1 | sed 's/CPU MHz:\s*//'
} > "$TMP_DIR/cpu_model.tmp"
write_section "===Модель процессора и частота===" < "$TMP_DIR/cpu_model.tmp"
grep "CPU(s):" "$TMP_DIR/cpu_info.tmp" | head -1 | sed 's/CPU(s):\s*//' | write_section "===Количество логических ядер==="
{
    grep "L1d cache" "$TMP_DIR/cpu_info.tmp" | sed 's/L1d cache:\s*//'
    grep "L1i cache" "$TMP_DIR/cpu_info.tmp" | sed 's/L1i cache:\s*//'
    grep "L2 cache"  "$TMP_DIR/cpu_info.tmp" | sed 's/L2 cache:\s*//'
    grep "L3 cache"  "$TMP_DIR/cpu_info.tmp" | sed 's/L3 cache:\s*//'
} > "$TMP_DIR/cpu_cache.tmp"
write_section "===Размеры кэша процессора всех уровней===" < "$TMP_DIR/cpu_cache.tmp"
grep "Mem:" "$TMP_DIR/memory_info.tmp" | awk '{print $2}' | write_section "===Объём физической памяти==="
write_section "===Название модели материнской платы===" < "$TMP_DIR/motherboard_info.tmp"
write_section "===Версия и дата выпуска BIOS===" < "$TMP_DIR/bios_info.tmp"
write_section "===Перечень всех устройств, подключённых к шине PCI===" < "$TMP_DIR/pci_info.tmp"

write_section "===Пользователи===" < <(build_users_report)
write_section "===Параметры sshd===" < <(build_sshd_report)
write_section "===Топ-5 процессов===" < <(head -6 "$TMP_DIR/top5_raw.tmp")
{
    echo "Пустой пароль в /etc/shadow:"
    if [ -s "$TMP_DIR/shadow_empty.tmp" ]; then sed 's/^/  /' "$TMP_DIR/shadow_empty.tmp"; else echo "  нет"; fi
    echo "UID 0 кроме root:"
    if [ -s "$TMP_DIR/uid0.tmp" ]; then sed 's/^/  /' "$TMP_DIR/uid0.tmp"; else echo "  нет"; fi
} > "$TMP_DIR/suspicious_report.tmp"
write_section "===Подозрительные учётные записи===" < "$TMP_DIR/suspicious_report.tmp"
if [ -s "$TMP_DIR/suid_raw.tmp" ]; then
    write_section "===Файлы с suid===" < "$TMP_DIR/suid_raw.tmp"
else
    write_section "===Файлы с suid===" < <(echo "нет данных")
fi
