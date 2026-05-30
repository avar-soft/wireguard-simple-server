#!/bin/bash
# shellcheck disable=SC2015,SC2129
# ╔══════════════════════════════════════════════════════════════╗
# ║   WireGuard Simple Server — v2.0 (patched-v13)               ║
# ║   Один сервер · Прямое подключение клиентов                  ║
# ║   nftables · sysctl hardening · UDP flood-лимит              ║
# ╚══════════════════════════════════════════════════════════════╝

set -uo pipefail

# ── Локаль ─────────────────────────────────────────────────────
if locale -a 2>/dev/null | grep -qx "C\.UTF-8\|C\.utf8"; then
    export LANG="${LANG:-C.UTF-8}"
    export LC_ALL="${LC_ALL:-C.UTF-8}"
else
    export LANG="${LANG:-C}"
    export LC_ALL="${LC_ALL:-C}"
fi

readonly VERSION="2.0"

# ── CHANGELOG (patched) ────────────────────────────────────────
# Исправления относительно оригинала v2.0:
#  #1  [КРИТИЧЕСКАЯ] Удалён Table = off из createServerConfig —
#      wg-quick теперь добавляет маршруты /32 к клиентам автоматически.
#  #2  [КРИТИЧЕСКАЯ] saveConfig: прямая запись > FILE заменена на
#      _atomic_write — защита от повреждения конфига при прерывании.
#  #3  [СЕРЬЁЗНАЯ]   nftables flood-правила: добавлен meta nfproto
#      для корректного матча IPv4/IPv6 в inet-таблице.
#  #4  [СЕРЬЁЗНАЯ]   revokeClient: python3 теперь с проверкой кода
#      возврата — тихий сбой удаления пира исключён.
#  #5  [СЕРЬЁЗНАЯ]   nftables: разрешены ICMP-типы необходимые для
#      PMTU Discovery (destination-unreachable, packet-too-big и др.)
#  #6  [СЕРЬЁЗНАЯ]   removeAll: добавлено удаление таблицы
#      ip6 wg-simple-nat6-* (ранее оставалась в памяти ядра).
#  #7  [УМЕРЕННАЯ]   loadConfig: eval для ALLOWED_IPS/ALLOWED_IPS6
#      заменён безопасным парсингом через grep/while read.
#  #8  [УМЕРЕННАЯ]   addClient: IPv6-адрес клиента формируется через
#      python3 ipaddress — корректно для любых форматов префикса.
# #11  [УМЕРЕННАЯ]   firstInstall: валидация IPv4/IPv6 CIDR через
#      python3 ipaddress.IPv4Network/IPv6Network.
# #14  [НЕЗНАЧИТЕЛЬНОЕ] _applyServerChanges: убран лишний
#      systemctl restart nftables (PostUp уже загружает конфиг).
#
# Дополнительные улучшения (некритичные):
#  I1  addClient: preshared-key читается из временного файла вместо
#      /dev/stdin — совместимость со старыми версиями WireGuard.
#  I2  installPackages / removeAll: chattr ±i теперь пропускается
#      внутри контейнеров (LXC/Docker) через _is_container().
#      Добавлена вспомогательная функция _is_container.
#  I3  loadConfig ALLOWED_IPS: парсинг через grep -oE безопасен —
#      IP/CIDR кавычек не содержат, уязвимость отсутствует.
#
# Патч v13 (DoH + исправления):
#  E1  [НОВОЕ]       _dns_setup_doh: добавлен DNS-over-HTTPS через dnsproxy.
#      dnsmasq → dnsproxy → HTTPS-апстрим. Провайдеры: Cloudflare, Google,
#      Quad9, AdGuard, Mullvad, NextDNS и ВСЕ сразу. DNS_MODE="doh".
#      dnsproxy скачивается с GitHub releases (go-binary, нет зависимостей).
#      Systemd-юнит /etc/systemd/system/dnsproxy.service создаётся автоматически.
#  E2  [ОШИБКА]      menuDns: пункт 3 «Перезапустить» содержал
#      case "${DNS_MODE:-dot}" — неверный fallback. При DNS_MODE=doh (и при plain)
#      не перезапускался бы нужный бэкенд. Исправлено на case "${DNS_MODE:-plain}",
#      добавлена ветка doh) systemctl restart dnsproxy.
#  E3  [ОШИБКА]      menuDns: пункты меню ссылались только на Unbound/DoT.
#      Добавлен пункт 3 (DoH), пункт «Перезапустить» стал 4.
#  E4  [ОШИБКА]      _dns_stop_all: не останавливал dnsproxy — при смене режима
#      doh→dot/unbound старый dnsproxy оставался на порту 5053.
#      Добавлены stop/disable для dnsproxy.
#  E5  [ОШИБКА]      removeAll: не удалял dnsproxy-юнит и бинарник.
#      Добавлены systemctl stop/disable dnsproxy, rm юнита и /usr/local/bin/dnsproxy.
#  E6  [ОШИБКА]      menuAutostart enable/disable/status: не включал/выключал
#      dnsproxy при DNS_MODE=doh. Добавлены соответствующие ветки.
#  E7  [ОШИБКА]      menuWGStatus / _statusBar: case по DNS_MODE не имел ветки doh —
#      при DoH режим отображался бы как «plain⚠». Добавлены ветки doh.
#  E8  [ОШИБКА]      firstInstall: вызов _dns_setup_dot без fallback на DoH.
#      Текст «Настройка зашифрованного DNS» теперь предлагает выбор DoT/DoH.
#      Добавлена переменная WG_DNS_BACKEND (dot|doh, по умолч. dot) для
#      автоматического режима.
#  E9  [ОШИБКА]      loadConfig/saveConfig: DNS_MODE="doh" корректно сохраняется
#      и читается — дополнительного кода не потребовалось (DNS_MODE — строка).
#
# Патч v12 (неинтерактивный режим):
#  D1  [УМЕРЕННАЯ]   _dns_setup_dot: добавлена поддержка переменной окружения
#      WG_DOT_PROVIDER (1..21). Если переменная задана — read пропускается,
#      скрипт использует переданное значение и не зависает без терминала.
#      Это позволяет запускать firstInstall полностью автоматически:
#        WG_DOT_PROVIDER=1 ./wg-for-tunel-dop.sh
#      или через pipe (для совместимости со старым способом):
#        echo "1" | ./wg-for-tunel-dop.sh
#      При отсутствии переменной поведение не меняется — интерактивный выбор.
#
# Патч v11 (совместимость Bash 4.3):
#  C5  menuSecurity удаление: ALLOWED_IPS=("${_new_arr[@]}") и
#      ALLOWED_IPS6=("${_new_arr6[@]}") заменены на явную проверку длины.
#      В Bash 4.3 (Ubuntu 16.04, Debian 8/9) "${empty_arr[@]}" при set -u
#      вызывает «unbound variable» даже для локально объявленного пустого
#      массива (local arr=()), что приводило к аварийному завершению при
#      удалении последнего IP из белого списка.
#      Идиома ${arr[@]+"${arr[@]}"} корректна в for-циклах, но внутри
#      arr=(...) может дать массив с одним пустым элементом. Единственный
#      надёжный обход — явная проверка [ "${#arr[@]}" -gt 0 ].
#
# Патч v10 (hotfix-2):
#  C3r createNft: исправлен порядок операций — nft -c (синтаксическая проверка)
#      перемещена ДО nft delete. Прежний порядок (delete → check → load)
#      оставлял сервер полностью без правил firewall если проверка падала:
#      таблицы уже удалены, новые не загружены, все порты открыты.
#      Новый порядок: check → delete → load.
#  C4  menuSecurity: "${_new_arr[@]:-}" и "${_new_arr6[@]:-}" заменены на
#      "${_new_arr[@]}" / "${_new_arr6[@]}". Синтаксис [@]:- некорректен
#      для массивов в bash и вызывает «bad substitution» на строгих версиях.
#      Массивы гарантированно инициализированы через declare -ag, поэтому
#      защита :-{} не нужна и вредна.
#
# Патч v9 (hotfix + улучшения):
#  B3r Откат ошибочного B3 (v8): ln -sf /dev/null /etc/resolv.conf ломал
#      apt-get update сразу после блока — установка пакетов прерывалась.
#      Возврат к корректной схеме: симлинк заменяется обычным файлом с
#      nameserver 127.0.0.1 (dnsmasq, запустится позже) + 1.1.1.1/8.8.8.8
#      как fallback; chattr +i защищает от перезаписи DHCP/NM.
#      Таргет оригинального симлинка сохраняется в resolv.conf.wg-bak-target
#      и восстанавливается как симлинк в removeAll.
#  C1  Все 12 циклов for _ip in "${ALLOWED_IPS[@]}" переведены на идиому
#      "${ARR[@]+"${ARR[@]}"}" — гарантирует отсутствие unbound variable
#      при set -u в Bash 4.3 на пустом массиве.
#  C2  audit_log добавлен в _dns_setup_plain/unbound/dot и menuAutostart
#      (enable/disable) — полный аудит изменений конфигурации.
#  C3  createNft: добавлен nft -c -f перед nft -f — синтаксическая проверка
#      до применения. При ошибке старые правила не удаляются и firewall
#      остаётся в рабочем состоянии.
#
# Патч v8 (аудит-4):
#  B1  addClient / firstInstall: все три места парсинга октетов IPv4 через
#      IFS=. read защищены от восьмеричной интерпретации — добавлен
#      принудительный десятичный базис: _o=$((10#${_o})).
#  B2  _applyKernelHardening: добавлен комментарий — net.ipv4.tcp_tw_reuse
#      удалён в Linux 5.17+ (поведение встроено в ядро). Ошибка при
#      sysctl -p на новых ядрах ожидаема и подавляется через || true.
#  B3  installPackages / removeAll: вместо rm -f + printf > /etc/resolv.conf
#      используется ln -sf /dev/null. Сохраняется оригинальный таргет симлинка
#      в resolv.conf.wg-bak-target для корректного восстановления в removeAll.
#  B4  _atomic_write: mktemp уже создавался в ${_dir} — это было корректно.
#      Добавлен явный комментарий о причине (атомарность rename(2) требует
#      одной ФС). Дополнительных изменений кода не потребовалось.
#  B5  safe_sed: функция была определена, но нигде не использовалась.
#      Удалена для уменьшения размера скрипта.
#  B6  Главное меню: нумерация исправлена на последовательную (1–10).
#      Пункт «Удалить всё» перенесён с позиции 8 в конец (позиция 10);
#      «Параметры сервера» и «Безопасность» стали 8 и 9 соответственно.
#  B7  backupConfig: добавлен путь
#      /etc/systemd/system/wg-quick@${SERVER_WG_NIC}.service.d
#      в список бэкапа — ранее override.conf терялся при переносе сервера.
#      (_autoBackup уже включал /etc/systemd/system целиком — изменений там нет.)
#
# Патч v7 (аудит-3):
#  A8  restoreConfig: путь к архиву проверяется на принадлежность
#      /var/backups/wg-simple/ — исключает случайную распаковку
#      произвольного tar в корень файловой системы.
#  A9  Глобальные массивы ALLOWED_IPS / ALLOWED_IPS6 переведены с
#      простого присваивания на declare -ag. При set -u bash гарантирует
#      что переменная существует и имеет тип массива до любого вызова
#      createNft / loadConfig, даже если CONFIG_FILE ещё не создан.
#
# Патч v6 (аудит-2):
#  A7  menuSecurity удаление: проверка на пустой белый список теперь
#      учитывает оба массива (ALLOWED_IPS и ALLOWED_IPS6). Ранее проверялся
#      только ALLOWED_IPS — при IPv6-only конфигурации меню сообщало
#      «Белый список пуст» и блокировало удаление IPv6-адресов.
#
# Патч v5 (совместимость):
#  A6  createNft: блок elements = { } в set allowed_hosts / allowed_hosts6
#      генерируется только при наличии элементов. Пустой блок вызывал
#      ошибку «syntax error» при загрузке конфига на nftables < 0.9.3
#      (Debian 10 Buster, Ubuntu 18.04). На современных дистрибутивах
#      поведение не меняется.
#
# Патч v4 (аудит):
#  A1  _is_container: явный whitelist контейнерных типов (docker, lxc,
#      openvz, podman, wsl, systemd-nspawn). KVM/VMware/Xen → return 1,
#      chattr там работает нормально.
#  A2  Заменены 3 вхождения "${#ALLOWED_IPS6[@]:-0}" на корректное
#      "${#ALLOWED_IPS6[@]}" (:-0 не работает с длиной массива).
#  A3  menuSecurity удаление: исправлен баг — IPv6-адреса теперь
#      корректно удаляются из ALLOWED_IPS6. Единый индекс для IPv4+IPv6.
#  A4  Валидация IP при добавлении в белый список (firstInstall и
#      menuSecurity) переведена на python3 ipaddress.ip_network —
#      отклоняет 999.x.x.x и другой мусор.
#  A5  net.ipv4.secure_redirects: 1 → 0. При accept_redirects=0
#      параметр неактивен; явный 0 убирает противоречие в конфиге.
# ───────────────────────────────────────────────────────────────



# ── ERR-trap ───────────────────────────────────────────────────
readonly WG_ERR_LOG="/var/log/wg-simple-trap.log"
mkdir -p "$(dirname "${WG_ERR_LOG}")" 2>/dev/null || true
touch "${WG_ERR_LOG}" 2>/dev/null && chmod 600 "${WG_ERR_LOG}" 2>/dev/null || true
_WG_INTERACTIVE=0
set -E
# shellcheck disable=SC2154
trap '_rc=$?; case "$_rc" in 0|130|141) :;; *)
  _src="${BASH_SOURCE[1]:-${BASH_SOURCE[0]:-main}}";
  _cmd="${BASH_COMMAND:-unknown}";
  case "${_cmd}" in read*|_pause*) :;; *)
  _msg=$(printf "[%s] %s:%s:%s rc=%s cmd: %s" "$(date +%H:%M:%S)" "${_src}" "${FUNCNAME[0]:-main}" "${BASH_LINENO[0]}" "$_rc" "${_cmd}");
  printf "%s\n" "$_msg" >> "${WG_ERR_LOG}" 2>/dev/null || true;
  [ "${WG_DEBUG:-0}" = "1" ] && printf "\033[1;31m[ERR]\033[0m %s\n" "$_msg" >&2;
  :;; esac;; esac' ERR

# ── Цвета ──────────────────────────────────────────────────────
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
WHITE='\033[1;37m'
DIM='\033[0;37m'
BOLD='\033[1m'
CYAN='\033[1;36m'
NC='\033[0m'

# ── Конфигурация ───────────────────────────────────────────────
SERVER_WG_NIC=""
MAIN_INTERFACE=""
SERVER_PORT=""
SERVER_MTU="1420"
CLIENT_IPV4_SUBNET=""
CLIENT_IPV6_SUBNET="fd13:22:31::/64"
SERVER_IPV4_ADDR=""
SERVER_IPV6_ADDR=""
SERVER_PUB_IP=""
SSH_PORT="22"
DNS_MODE="plain"
ENABLE_IPV6="yes"
CONFIG_FILE="/etc/wireguard/.wg-simple.conf"

# Белые списки IP (заполняются при установке и через меню безопасности)
# declare -ag: явный тип массива + global — безопасно при set -u и
# при повторном вызове loadConfig из подфункций.
declare -ag ALLOWED_IPS=()    # IPv4 адреса/CIDR с полным входящим доступом
declare -ag ALLOWED_IPS6=()   # IPv6 адреса/CIDR с полным входящим доступом

# ── Утилиты вывода ─────────────────────────────────────────────
info()    { echo -e "  ${GREEN}[✔]${NC} $*"; }
warn()    { echo -e "  ${YELLOW}[!]${NC} $*"; }
error()   { echo -e "  ${RED}[✗]${NC} $*" >&2; exit 1; }
step()    { echo -e "\n  ${CYAN}▶${NC} ${BOLD}$*${NC}"; }
section() { echo -e "\n  ${YELLOW}━━  $*  ━━${NC}"; }
hint()    { echo -e "  ${DIM}ℹ $*${NC}"; }
must()    { "$@" || error "FATAL: команда завершилась с ошибкой: $*"; }

_pause()  { echo ""; read -rp "  [Enter] — продолжить..." _dummy; }

# ── _is_container ──────────────────────────────────────────────
# Возвращает 0 (true) если скрипт выполняется внутри контейнера
# (Docker, LXC, OpenVZ, systemd-nspawn и т.п.)
_is_container() {
    # systemd-detect-virt — самый надёжный способ.
    # Исправление A1: явный whitelist контейнерных окружений.
    # KVM, QEMU, VMware, Xen, Hyper-V — обычные VM, chattr там работает → return 1.
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        case "$(systemd-detect-virt 2>/dev/null)" in
            docker|lxc|lxc-libvirt|openvz|podman|wsl|systemd-nspawn)
                return 0 ;;  # контейнер — chattr запрещён ядром хоста
            none|kvm|qemu|vmware|microsoft|xen|bochs|uml|parallels)
                return 1 ;;  # bare metal или полноценная VM
            *)
                return 1 ;;  # неизвестное окружение — не блокируем chattr
        esac
    fi
    # Запасной вариант: ищем .dockerenv или cgroup-маркеры контейнеров
    [ -f /.dockerenv ] && return 0
    grep -qE 'docker|lxc|kubepods|containerd' /proc/1/cgroup 2>/dev/null && return 0
    return 1
}



# ── _atomic_write ──────────────────────────────────────────────
_atomic_write() {
    local _dst="$1" _mode="${2:-600}"
    local _dir _tmp
    _dir=$(dirname "${_dst}")
    mkdir -p "${_dir}" 2>/dev/null || true
    # Исправление B4: mktemp в той же директории что и _dst — гарантирует
    # что mv является атомарной операцией rename(2) на уровне ФС.
    # mktemp в /tmp при /etc на другой ФС приводит к cp+rm, что не атомарно.
    _tmp=$(mktemp "${_dir}/.atomic_XXXXXX") || { warn "_atomic_write: mktemp failed"; return 1; }
    if ! cat > "${_tmp}"; then
        rm -f "${_tmp}"; return 1
    fi
    chmod "${_mode}" "${_tmp}" 2>/dev/null || true
    mv -f "${_tmp}" "${_dst}" || { rm -f "${_tmp}"; return 1; }
}

# ── Валидация ──────────────────────────────────────────────────
isRoot() {
    [ "${EUID}" -eq 0 ] || error "Запускай от root!"
}

checkBashVersion() {
    local major="${BASH_VERSINFO[0]}" minor="${BASH_VERSINFO[1]}"
    (( major < 4 || (major == 4 && minor < 3) )) && \
        error "Требуется bash >= 4.3. Установлена: ${BASH_VERSION}"
}

validateIfaceName() {
    _validIfaceName "${1}" || \
        error "Недопустимое имя интерфейса: '${1}'"
}

validateClientName() {
    [[ "${1}" =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$ ]] || \
        error "Недопустимое имя клиента: '${1}' (только a-z, 0-9, _, -, первый символ — буква/цифра, макс 32)"
}

validateInterface() {
    ip link show "${1}" >/dev/null 2>&1 || error "Интерфейс '${1}' не найден"
}

# ── audit_log ──────────────────────────────────────────────────
_AUDIT_LOG="/var/log/wg-simple-audit.log"
audit_log() {
    local _user="${SUDO_USER:-${USER:-root}}"
    printf "[%s] user=%s action=%s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "${_user}" "$*" \
        >> "${_AUDIT_LOG}" 2>/dev/null || true
}

# ── _autoBackup ────────────────────────────────────────────────
_autoBackup() {
    local _tag="${1:-pre-op}" _dir="/var/backups/wg-simple"
    local _ts _file
    _ts=$(date +%Y%m%d-%H%M%S)
    _file="${_dir}/${_tag}-${_ts}.tar.gz"
    mkdir -p "${_dir}" 2>/dev/null || return 1
    local _list=()
    local _p
    for _p in /etc/wireguard /etc/nftables.conf /etc/systemd/system; do
        [ -e "${_p}" ] && _list+=("${_p}")
    done
    [ "${#_list[@]}" -eq 0 ] && return 1
    tar czf "${_file}" --warning=no-file-changed --warning=no-file-removed \
        --exclude='/etc/systemd/system/multi-user.target.wants' \
        "${_list[@]}" 2>/dev/null || true
    if [ -s "${_file}" ]; then
        echo "  [backup] ${_file}" >&2
        find "${_dir}" -maxdepth 1 -name "*.tar.gz" | sort -r | tail -n +11 | xargs -r rm -f
        return 0
    fi
    rm -f "${_file}"; return 1
}

# ── saveConfig / loadConfig ────────────────────────────────────
saveConfig() {
    mkdir -p "$(dirname "${CONFIG_FILE}")"
    {
        printf 'SERVER_WG_NIC="%s"\n'      "${SERVER_WG_NIC}"
        printf 'MAIN_INTERFACE="%s"\n'     "${MAIN_INTERFACE}"
        printf 'SERVER_PORT="%s"\n'        "${SERVER_PORT}"
        printf 'SERVER_MTU="%s"\n'         "${SERVER_MTU:-1420}"
        printf 'CLIENT_IPV4_SUBNET="%s"\n' "${CLIENT_IPV4_SUBNET}"
        printf 'CLIENT_IPV6_SUBNET="%s"\n' "${CLIENT_IPV6_SUBNET}"
        printf 'SERVER_IPV4_ADDR="%s"\n'   "${SERVER_IPV4_ADDR}"
        printf 'SERVER_IPV6_ADDR="%s"\n'   "${SERVER_IPV6_ADDR}"
        printf 'SERVER_PUB_IP="%s"\n'      "${SERVER_PUB_IP}"
        printf 'SSH_PORT="%s"\n'           "${SSH_PORT}"
        printf 'DNS_MODE="%s"\n'           "${DNS_MODE:-plain}"
        printf 'ENABLE_IPV6="%s"\n'        "${ENABLE_IPV6:-yes}"
        # Белые списки: каждый IP на отдельной строке
        printf 'ALLOWED_IPS=('
        local _ip
        for _ip in "${ALLOWED_IPS[@]+"${ALLOWED_IPS[@]}"}"; do
            [ -n "${_ip}" ] && printf ' "%s"' "${_ip}"
        done
        printf ' )\n'
        printf 'ALLOWED_IPS6=('
        for _ip in "${ALLOWED_IPS6[@]+"${ALLOWED_IPS6[@]}"}"; do
            [ -n "${_ip}" ] && printf ' "%s"' "${_ip}"
        done
        printf ' )\n'
    } | _atomic_write "${CONFIG_FILE}" 600
}

_validIfaceName() { [[ "${1}" =~ ^[A-Za-z][A-Za-z0-9_-]{0,14}$ ]]; }

loadConfig() {
    [ -f "${CONFIG_FILE}" ] || return 0
    local _lc_line _lc_key _lc_val
    while IFS= read -r _lc_line || [ -n "${_lc_line}" ]; do
        [[ "${_lc_line}" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${_lc_line// }" ]] && continue
        [[ "${_lc_line}" != *=* ]] && continue
        _lc_key="${_lc_line%%=*}"; _lc_val="${_lc_line#*=}"
        _lc_key="${_lc_key#"${_lc_key%%[![:space:]]*}"}"; _lc_key="${_lc_key%"${_lc_key##*[![:space:]]}"}"
        _lc_val="${_lc_val#"${_lc_val%%[![:space:]]*}"}"; _lc_val="${_lc_val%"${_lc_val##*[![:space:]]}"}"
        _lc_val="${_lc_val%$'\r'}"
        if [[ "${_lc_val}" == \"*\" ]]; then
            _lc_val="${_lc_val#\"}"; _lc_val="${_lc_val%\"}"
            _lc_val="${_lc_val//\\\"/\"}"; _lc_val="${_lc_val//\\\\/\\}"
        fi
        case "${_lc_key}" in
            SERVER_WG_NIC|MAIN_INTERFACE|SERVER_PORT|SERVER_MTU|\
            CLIENT_IPV4_SUBNET|CLIENT_IPV6_SUBNET|SERVER_IPV4_ADDR|\
            SERVER_IPV6_ADDR|SERVER_PUB_IP|SSH_PORT|DNS_MODE|ENABLE_IPV6)
                printf -v "${_lc_key}" '%s' "${_lc_val}" ;;
            ALLOWED_IPS)
                # Исправление #7: безопасный парсинг массива без eval
                # Формат: ( "ip1" "ip2" ) → извлекаем значения в кавычках
                ALLOWED_IPS=()
                local _raw_v="${_lc_val#(}"; _raw_v="${_raw_v%)}"
                while IFS= read -r _item; do
                    [ -n "${_item}" ] && ALLOWED_IPS+=("${_item}")
                done < <(printf '%s
' "${_raw_v}" | grep -oE '"[^"]+"' | tr -d '"')
                ;;
            ALLOWED_IPS6)
                ALLOWED_IPS6=()
                local _raw_v6="${_lc_val#(}"; _raw_v6="${_raw_v6%)}"
                while IFS= read -r _item; do
                    [ -n "${_item}" ] && ALLOWED_IPS6+=("${_item}")
                done < <(printf '%s
' "${_raw_v6}" | grep -oE '"[^"]+"' | tr -d '"')
                ;;
        esac
    done < "${CONFIG_FILE}"

    # Валидация после загрузки
    if [ -n "${SERVER_WG_NIC:-}" ] && ! _validIfaceName "${SERVER_WG_NIC}"; then
        echo "FATAL: SERVER_WG_NIC='${SERVER_WG_NIC}' содержит недопустимые символы" >&2; exit 2
    fi
    if [ -n "${MAIN_INTERFACE:-}" ] && ! _validIfaceName "${MAIN_INTERFACE}"; then
        echo "FATAL: MAIN_INTERFACE='${MAIN_INTERFACE}' содержит недопустимые символы" >&2; exit 2
    fi
}

# ── ask / askYesNo ─────────────────────────────────────────────
ask() {
    local _prompt="$1" _hint="$2" _var="$3" _default="$4"
    local _val
    [ -n "${_hint}" ] && hint "${_hint}"
    local _cur="${!_var:-}"
    local _show_default="${_default}"
    [ -n "${_cur}" ] && _show_default="${_cur}"
    echo -ne "  ${CYAN}→ ${_prompt}${NC}"
    [ -n "${_show_default}" ] && echo -ne " ${DIM}[${_show_default}]${NC}"
    echo -ne ": "
    _WG_INTERACTIVE=1; read -r _val; _WG_INTERACTIVE=0
    if [ -z "${_val}" ]; then
        [ -n "${_cur}" ] && return 0
        [ -n "${_default}" ] && _val="${_default}"
    fi
    [ -n "${_val}" ] && printf -v "${_var}" '%s' "${_val}"
}

askYesNo() {
    local _prompt="$1" _var="$2" _default="${3:-y}"
    local _ans
    echo -ne "  ${CYAN}→ ${_prompt}${NC} ${DIM}[y/n, по умолч.: ${_default}]${NC}: "
    _WG_INTERACTIVE=1; read -r _ans; _WG_INTERACTIVE=0
    [ -z "${_ans}" ] && _ans="${_default}"
    case "${_ans}" in
        y|Y|yes|YES|д|Д) printf -v "${_var}" 'yes' ;;
        *)                 printf -v "${_var}" 'no'  ;;
    esac
}

# ════════════════════════════════════════════════════════════════
# УСТАНОВКА ПАКЕТОВ
# ════════════════════════════════════════════════════════════════
installPackages() {
    step "Установка пакетов"

    # Освобождаем порт 53 если занят systemd-resolved
    if systemctl is-active --quiet systemd-resolved 2>/dev/null \
       || systemctl is-enabled --quiet systemd-resolved 2>/dev/null; then
        info "Освобождаю :53 от systemd-resolved"
        systemctl stop systemd-resolved 2>/dev/null || true
        systemctl disable systemd-resolved 2>/dev/null || true
        mkdir -p /etc/systemd/resolved.conf.d
        cat > /etc/systemd/resolved.conf.d/99-wireguard.conf << 'EOF'
[Resolve]
DNSStubListener=no
EOF
        if [ -L /etc/resolv.conf ]; then
            # Исправление B3 (rev2): симлинк заменяем обычным файлом с работающими
            # nameserver-ами. /dev/null (предыдущий подход) ломал apt-get update и любой
            # DNS-резолвинг на сервере. Оригинальный таргет симлинка сохраняем для
            # восстановления в removeAll. chattr +i защищает файл от перезаписи DHCP/NM.
            readlink /etc/resolv.conf > /etc/resolv.conf.wg-bak-target 2>/dev/null || true
            cp -f /etc/resolv.conf /etc/resolv.conf.wg-bak 2>/dev/null || true
            rm -f /etc/resolv.conf
            # 127.0.0.1 — dnsmasq (запустится позже); 1.1.1.1 — fallback пока dnsmasq не поднят
            printf 'nameserver 127.0.0.1\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n' \
                > /etc/resolv.conf
            if ! _is_container && command -v chattr >/dev/null 2>&1; then
                chattr +i /etc/resolv.conf 2>/dev/null \
                    && info "resolv.conf защищён (chattr +i)" \
                    || warn "chattr +i не удался — resolv.conf может быть перезаписан DHCP"
            else
                hint "Контейнер или chattr недоступен — пропускаем chattr +i /etc/resolv.conf"
            fi
        fi
    fi

    apt-get update -q
    apt-get install -y wireguard nftables curl iproute2 qrencode \
        dnsutils cron iputils-ping nano net-tools wget dnsmasq \
        ca-certificates openssl python3 xxd
    info "Пакеты установлены"
}

# ════════════════════════════════════════════════════════════════
# IP FORWARDING
# ════════════════════════════════════════════════════════════════
enableForwarding() {
    step "Включение IP forwarding (IPv4 + IPv6)"
    sysctl -w net.ipv4.ip_forward=1               >/dev/null
    sysctl -w net.ipv6.conf.all.forwarding=1      >/dev/null
    sysctl -w net.ipv4.conf.all.rp_filter=2       >/dev/null
    sysctl -w net.ipv4.conf.default.rp_filter=2   >/dev/null
    cat > /etc/sysctl.d/99-wg-simple.conf << 'EOF'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
EOF
    sysctl -p /etc/sysctl.d/99-wg-simple.conf >/dev/null
    info "IP forwarding включён"
}

# ════════════════════════════════════════════════════════════════
# HARDENING ЯДРА — МАКСИМАЛЬНЫЙ УРОВЕНЬ
# ════════════════════════════════════════════════════════════════
_applyKernelHardening() {
    step "Hardening ядра — максимальный уровень"

    # ── conntrack: увеличиваем лимит таблицы соединений ──────────
    if [ -f /proc/sys/net/netfilter/nf_conntrack_max ]; then
        echo 1000000 > /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || true
    fi

    # ── IPv4: rp_filter=2 (LOOSE) — обязательно для WireGuard ────
    # strict(=1) ломает асимметричную маршрутизацию туннеля
    sysctl -w net.ipv4.conf.all.rp_filter=2          >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.default.rp_filter=2      >/dev/null 2>&1 || true

    # ── TCP SYN Cookies — защита от SYN-flood ────────────────────
    sysctl -w net.ipv4.tcp_syncookies=1              >/dev/null 2>&1 || true

    # ── Анти-спуфинг: блокировать IP source routing ──────────────
    sysctl -w net.ipv4.conf.all.accept_source_route=0   >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.default.accept_source_route=0 >/dev/null 2>&1 || true

    # ── ICMP редиректы — вектор MITM, отключаем ─────────────────
    sysctl -w net.ipv4.conf.all.accept_redirects=0   >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.default.accept_redirects=0 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.all.send_redirects=0     >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.default.send_redirects=0 >/dev/null 2>&1 || true
    # Исправление A5: при accept_redirects=0 параметр secure_redirects неактивен.
    # Явно выставляем 0 для консистентности конфига.
    sysctl -w net.ipv4.secure_redirects=0            >/dev/null 2>&1 || true

    # ── ICMP: игнорировать broadcast (Smurf), bogus-errors ───────
    sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1    >/dev/null 2>&1 || true
    sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1 >/dev/null 2>&1 || true

    # ── Логировать «мартианские» пакеты ──────────────────────────
    sysctl -w net.ipv4.conf.all.log_martians=1          >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.default.log_martians=1      >/dev/null 2>&1 || true

    # ── TCP hardening ─────────────────────────────────────────────
    # Рандомизация портов — усложняет предсказание TCP sequence
    sysctl -w net.ipv4.ip_local_port_range="1024 65535" >/dev/null 2>&1 || true
    # Уменьшаем время ожидания SYN-ACK — быстрее освобождаем half-open очередь
    sysctl -w net.ipv4.tcp_synack_retries=2             >/dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_syn_retries=3                >/dev/null 2>&1 || true
    # TIME_WAIT reuse — позволяет быстро переиспользовать порты.
    # Замечание B2: параметр удалён из ядра Linux 5.17+ (всегда включён внутри).
    # Ошибка "No such file" на новых ядрах подавляется через || true — это ожидаемо.
    sysctl -w net.ipv4.tcp_tw_reuse=1                   >/dev/null 2>&1 || true
    # Защита от атак через некорректный fin_timeout
    sysctl -w net.ipv4.tcp_fin_timeout=15               >/dev/null 2>&1 || true
    # Максимум запросов в очереди ожидания SYN
    sysctl -w net.ipv4.tcp_max_syn_backlog=4096         >/dev/null 2>&1 || true

    # ── IPv6 ─────────────────────────────────────────────────────
    sysctl -w net.ipv6.conf.all.accept_redirects=0      >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.default.accept_redirects=0  >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.all.accept_source_route=0   >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.all.accept_ra=0             >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.default.accept_ra=0         >/dev/null 2>&1 || true

    # ── Kernel ASLR — максимальная рандомизация адресов ──────────
    sysctl -w kernel.randomize_va_space=2               >/dev/null 2>&1 || true

    # ── Защита /proc от утечек информации ────────────────────────
    sysctl -w kernel.kptr_restrict=2                    >/dev/null 2>&1 || true
    sysctl -w kernel.dmesg_restrict=1                   >/dev/null 2>&1 || true

    # ── Persist в sysctl.d (перезаписываем всегда — актуальные значения) ──
    local _harden_conf="/etc/sysctl.d/99-wg-hardening.conf"
    cat > "${_harden_conf}" << 'SYSCTLEOF'
# WireGuard Server — МАКСИМАЛЬНЫЙ HARDENING ЯДРА
# Автоматически сгенерировано wg-server.sh

# ── IP forwarding (WireGuard туннель) ──────────────────────────
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1

# ── rp_filter=2 ОБЯЗАТЕЛЕН для WireGuard (loose mode) ─────────
# strict(=1) ломает асимметричную маршрутизацию туннеля
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2

# ── TCP hardening ─────────────────────────────────────────────
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_synack_retries=2
net.ipv4.tcp_syn_retries=3
# tcp_tw_reuse удалён в ядре 5.17+ (поведение включено постоянно).
# На старых ядрах строка активна; на новых sysctl -p выдаст предупреждение — это норма.
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_max_syn_backlog=4096
net.ipv4.ip_local_port_range=1024 65535

# ── Анти-спуфинг ─────────────────────────────────────────────
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.secure_redirects=0

# ── ICMP защита ───────────────────────────────────────────────
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1

# ── IPv6 ─────────────────────────────────────────────────────
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0

# ── Kernel security ───────────────────────────────────────────
kernel.randomize_va_space=2
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
SYSCTLEOF

    sysctl -p "${_harden_conf}" >/dev/null 2>&1 || true

    info "Kernel hardening применён (максимальный уровень)"
    info "SYN cookies · rp_filter=loose · анти-спуфинг · ASLR=2 · kptr_restrict=2"
    hint "Конфиг: ${_harden_conf}"
}

# ════════════════════════════════════════════════════════════════
# NFTABLES — МАКСИМАЛЬНАЯ ЗАЩИТА
# Политика: INPUT=DROP, FORWARD=DROP, OUTPUT=ACCEPT
# Входящие: только явно разрешённые IP + WG-порт
# Исходящие: без ограничений (NTP, DNS, apt, мониторинг)
# ════════════════════════════════════════════════════════════════
createNft() {
    step "Настройка nftables (максимальная защита)"

    local _tbl_filter="wg-simple-filter-${SERVER_WG_NIC}"
    local _tbl_nat="wg-simple-nat-${SERVER_WG_NIC}"

    # ── Формируем список разрешённых IP ──────────────────────────
    # ALLOWED_IPS — массив, заполняется в firstInstall или menuSecurity
    local _allowed_elements=""
    local _ip
    if [ "${#ALLOWED_IPS[@]}" -gt 0 ]; then
        for _ip in "${ALLOWED_IPS[@]+"${ALLOWED_IPS[@]}"}"; do
            [ -n "${_ip}" ] && _allowed_elements+="        ${_ip},
"
        done
    fi

    # ── Формируем список разрешённых IP для IPv6 ─────────────────
    local _allowed6_elements=""
    if [ "${#ALLOWED_IPS6[@]}" -gt 0 ] 2>/dev/null; then
        for _ip in "${ALLOWED_IPS6[@]+"${ALLOWED_IPS6[@]}"}"; do
            [ -n "${_ip}" ] && _allowed6_elements+="        ${_ip},
"
        done
    fi

    # Исправление A6: блок elements = { } генерируется только при наличии
    # элементов — пустой блок вызывал ошибку загрузки на nftables < 0.9.3
    # (Debian 10 Buster, Ubuntu 18.04 и ряд старых ядер).
    local _set4_body="        type ipv4_addr
        flags interval"
    [ -n "${_allowed_elements}" ] && _set4_body+="
        elements = {
${_allowed_elements}        }"

    local _set6_body="        type ipv6_addr
        flags interval"
    [ -n "${_allowed6_elements}" ] && _set6_body+="
        elements = {
${_allowed6_elements}        }"

    local _nft_content
    _nft_content="#!/usr/sbin/nft -f
# WireGuard Simple Server — авто-сгенерировано v${VERSION}
# РЕЖИМ: МАКСИМАЛЬНАЯ ЗАЩИТА
# INPUT=DROP  FORWARD=DROP  OUTPUT=ACCEPT
# Таблицы привязаны к интерфейсу: ${SERVER_WG_NIC}

table inet ${_tbl_filter} {

    # ── Белый список IPv4: полный доступ ─────────────────────────
    set allowed_hosts {
${_set4_body}
    }

    # ── Белый список IPv6: полный доступ ─────────────────────────
    set allowed_hosts6 {
${_set6_body}
    }

    # ── WG UDP flood-лимит: per-IP rate limit ────────────────────
    # WireGuard не отвечает на неаутентифицированные пакеты,
    # поэтому UDP rate-limit по srcip — достаточная защита от флуда.
    set wg_flood_v4 {
        type ipv4_addr
        flags dynamic, timeout
        timeout 10s
    }
    set wg_flood_v6 {
        type ipv6_addr
        flags dynamic, timeout
        timeout 10s
    }

    # ── TCP аномальные флаги (NULL/XMAS/SYN+FIN/SYN+RST/FIN) ────
    # Обнаруживают сканирование портов — DROP до любых ACCEPT правил
    chain prerouting_raw {
        type filter hook prerouting priority raw; policy accept;
        # NULL scan
        tcp flags == 0x0                              drop
        # XMAS scan
        tcp flags & (fin|psh|urg) == fin|psh|urg     drop
        # SYN + FIN (невалидная комбинация)
        tcp flags & (syn|fin) == syn|fin              drop
        # SYN + RST (невалидная комбинация)
        tcp flags & (syn|rst) == syn|rst              drop
        # FIN без ACK
        tcp flags & (fin|ack) == fin                  drop
    }

    # ── INPUT: политика DROP, разрешаем явно ────────────────────
    chain input {
        type filter hook input priority filter; policy drop;

        # 1. Loopback — всегда разрешён
        iifname lo accept

        # 2. ESTABLISHED/RELATED — ответы на наши исходящие соединения
        ct state established,related accept

        # 3. INVALID пакеты — дроп (не нужны даже для conntrack)
        ct state invalid drop

        # 4. WireGuard UDP порт — flood-лимит + accept
        #    200 pkt/s per srcIP, burst 800; превышение — DROP
        udp dport ${SERVER_PORT} meta nfproto ipv4 \
            add @wg_flood_v4 { ip saddr limit rate over 200/second burst 800 packets } \
            drop
        udp dport ${SERVER_PORT} meta nfproto ipv6 \
            add @wg_flood_v6 { ip6 saddr limit rate over 200/second burst 800 packets } \
            drop
        udp dport ${SERVER_PORT} accept

        # 5. DNS от WG-клиентов к локальному dnsmasq
        iifname \"${SERVER_WG_NIC}\" udp dport 53 accept
        iifname \"${SERVER_WG_NIC}\" tcp dport 53 accept

        # 6. Белый список IP — полный доступ (SSH, любые порты)
        ip  saddr @allowed_hosts  accept
        ip6 saddr @allowed_hosts6 accept

        # 7. ICMP — разрешаем только типы необходимые для PMTU Discovery и диагностики.
        #    echo-request от белых IP уже пропущены пунктом 6.
        #    Исправление #5: полный DROP ICMP ломает PMTU Discovery (Fragmentation Needed / Packet Too Big),
        #    что вызывает зависание TCP-соединений при нестандартном MTU WireGuard.
        ip  protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept
        ip6 nexthdr icmpv6 icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept
        ip  protocol icmp   drop
        ip6 nexthdr  icmpv6 drop

        # 8. Всё остальное — DROP (политика цепочки)
        # Логируем отброшенное (опционально, лимит 3/мин — не засоряет syslog)
        limit rate 3/minute log prefix \"[WG-DROP-IN] \" level warn
        drop
    }

    # ── OUTPUT: без ограничений ──────────────────────────────────
    # NTP критичен для WireGuard (метки Tai64N)
    # apt, DNS, мониторинг — сервер может инициировать любые соединения
    chain output {
        type filter hook output priority filter; policy accept;
    }

    # ── FORWARD: только WG-трафик, MSS clamping ─────────────────
    chain forward {
        type filter hook forward priority filter; policy drop;

        # ESTABLISHED/RELATED — ответы уже установленных соединений туннеля
        ct state established,related counter accept

        # INVALID — дроп немедленно
        ct state invalid drop

        # WG → Internet (клиенты выходят через сервер)
        iifname \"${SERVER_WG_NIC}\" oifname \"${MAIN_INTERFACE}\" counter accept

        # Internet → WG (ответные пакеты; уже покрыто ESTABLISHED выше,
        # но явное правило нагляднее и страхует от edge-cases)
        iifname \"${MAIN_INTERFACE}\" oifname \"${SERVER_WG_NIC}\" ct state established,related counter accept

        # MSS Clamping: предотвращает залипание HTTPS при нестандартном MTU
        iifname \"${SERVER_WG_NIC}\" tcp flags syn tcp option maxseg size set rt mtu
        iifname \"${MAIN_INTERFACE}\" tcp flags syn tcp option maxseg size set rt mtu

        # Всё остальное — лог + дроп
        limit rate 3/minute log prefix \"[WG-DROP-FWD] \" level warn
        drop
    }
}

table inet ${_tbl_nat} {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname \"${MAIN_INTERFACE}\" masquerade
    }
}"

    # IPv6 NAT — добавляем один раз
    if [ "${ENABLE_IPV6:-yes}" = "yes" ] && [ -n "${SERVER_IPV6_ADDR:-}" ]; then
        _nft_content+="

table ip6 wg-simple-nat6-${SERVER_WG_NIC} {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname \"${MAIN_INTERFACE}\" masquerade
    }
}"
    fi

    printf '%s\n' "${_nft_content}" | _atomic_write /etc/nftables.conf 644

    # Удаляем старые таблицы перед загрузкой — иначе "File exists"
    # Исправление C3r: порядок операций изменён для исключения окна без firewall.
    # 1. Сначала проверяем синтаксис — ядро не трогаем.
    # 2. Только при успехе удаляем старые таблицы и загружаем новые.
    # Прежний порядок (delete → check → load) оставлял сервер без правил
    # если nft -c обнаруживал ошибку после уже выполненного delete.
    nft -c -f /etc/nftables.conf || error "nftables: синтаксическая ошибка в конфиге — firewall не изменён"
    nft delete table inet "wg-simple-filter-${SERVER_WG_NIC}" 2>/dev/null || true
    nft delete table inet "wg-simple-nat-${SERVER_WG_NIC}"    2>/dev/null || true
    nft delete table ip6  "wg-simple-nat6-${SERVER_WG_NIC}"   2>/dev/null || true
    nft -f /etc/nftables.conf || error "nftables: ошибка загрузки конфига"
    systemctl enable nftables 2>/dev/null || true
    info "nftables: INPUT=DROP, FORWARD=DROP, OUTPUT=ACCEPT"
    if [ "${#ALLOWED_IPS[@]}" -gt 0 ]; then
        info "Разрешённые IP: ${ALLOWED_IPS[*]}"
    else
        warn "Белый список пуст — входящие заблокированы (кроме WG-порта)"
    fi
    info "WG UDP/${SERVER_PORT}: flood-лимит 200pps/IP + accept"
}

# ════════════════════════════════════════════════════════════════
# КОНФИГ WIREGUARD
# ════════════════════════════════════════════════════════════════
createServerConfig() {
    step "Создание серверного конфига WireGuard"
    mkdir -p /etc/wireguard
    chmod 700 /etc/wireguard

    # Генерируем ключ только если нет
    [ ! -f /etc/wireguard/server_private.key ] && \
        (umask 077; wg genkey > /etc/wireguard/server_private.key)
    chmod 600 /etc/wireguard/server_private.key

    local SERVER_PRIV_KEY SERVER_PUB_KEY
    SERVER_PRIV_KEY=$(cat /etc/wireguard/server_private.key)
    SERVER_PUB_KEY=$(wg pubkey < /etc/wireguard/server_private.key)

    local _sconf="/etc/wireguard/${SERVER_WG_NIC}.conf"

    # Собираем существующие пиры если конфиг уже есть
    local _existing_peers=""
    if [ -f "${_sconf}" ]; then
        _existing_peers=$(python3 - "${_sconf}" << 'PYEOF'
import sys, re
path = sys.argv[1]
try:
    with open(path) as f:
        data = f.read().replace('\r\n', '\n').replace('\r', '\n')
except:
    sys.exit(0)
parts = re.split(r'(?m)^(?=[ \t]*\[Peer\][ \t]*$)', data)
peers = [p for p in parts if p.lstrip().startswith('[Peer]')]
print(''.join(peers), end='')
PYEOF
)
    fi

    {
        # IPv6 опционален — не добавляем если отключён
        local _addr_line="${SERVER_IPV4_ADDR}"
        [ "${ENABLE_IPV6:-yes}" = "yes" ] && [ -n "${SERVER_IPV6_ADDR:-}" ] && \
            _addr_line="${SERVER_IPV4_ADDR}, ${SERVER_IPV6_ADDR}"
        printf '[Interface]\nPrivateKey = %s\nAddress = %s\nListenPort = %s\nMTU = %s\n' \
            "${SERVER_PRIV_KEY}" "${_addr_line}" \
            "${SERVER_PORT}" "${SERVER_MTU:-1420}"
        printf '# PostUp/PostDown: включаем masquerade через nftables (reload)\n'
        printf 'PostUp   = nft -f /etc/nftables.conf\n'
        printf 'PostDown = nft delete table inet wg-simple-filter-%s 2>/dev/null || true; nft delete table inet wg-simple-nat-%s 2>/dev/null || true; nft delete table ip6 wg-simple-nat6-%s 2>/dev/null || true\n' \
            "${SERVER_WG_NIC}" "${SERVER_WG_NIC}" "${SERVER_WG_NIC}"
        printf '\n'
        [ -n "${_existing_peers}" ] && printf '%s\n' "${_existing_peers}"
    } | _atomic_write "${_sconf}" 600

    info "Публичный ключ сервера: ${GREEN}${SERVER_PUB_KEY}${NC}"
    info "Конфиг: ${_sconf}"
}

# ════════════════════════════════════════════════════════════════
# DNSMASQ — простой DNS для клиентов
# ════════════════════════════════════════════════════════════════
setupDnsmasq() {
    step "Настройка dnsmasq"
    local _wg_ip="${SERVER_IPV4_ADDR%%/*}"

    # bind-dynamic позволяет dnsmasq стартовать до поднятия WG-интерфейса
    # listen-address=127.0.0.1 — резолвер всегда доступен локально
    cat > /etc/dnsmasq.d/wg-simple.conf << EOF
# WireGuard Simple Server — dnsmasq
# Слушаем только на WG-интерфейсе — защита от Open Resolver
interface=${SERVER_WG_NIC}
bind-dynamic
listen-address=127.0.0.1
listen-address=${_wg_ip}
server=1.1.1.1
server=8.8.8.8
no-resolv
no-poll
cache-size=1000
log-queries=no
EOF

    # Отключаем resolvconf-интеграцию dnsmasq
    if [ -f /etc/default/dnsmasq ]; then
        sed -i 's/^#*IGNORE_RESOLVCONF=.*/IGNORE_RESOLVCONF=yes/' /etc/default/dnsmasq
        grep -q '^IGNORE_RESOLVCONF' /etc/default/dnsmasq || \
            echo 'IGNORE_RESOLVCONF=yes' >> /etc/default/dnsmasq
    fi

    # ExecStartPre: ждём WG-интерфейс (решает "Cannot assign requested address")
    # exit 1 при таймауте — systemd получит ошибку и выполнит Restart=on-failure
    mkdir -p /etc/systemd/system/dnsmasq.service.d
    cat > /etc/systemd/system/dnsmasq.service.d/wg-wait.conf << OVERRIDE
[Service]
ExecStartPre=/bin/sh -c 'for i in 1 2 3 4 5 6 7 8 9 10; do ip addr show ${SERVER_WG_NIC} 2>/dev/null | grep -q "inet " && exit 0; sleep 1; done; exit 1'
OVERRIDE
    systemctl daemon-reload 2>/dev/null || true

    # Проверка конфига перед запуском
    if dnsmasq --test 2>/dev/null; then
        systemctl enable --now dnsmasq 2>/dev/null || \
            warn "dnsmasq не стартовал — проверь: journalctl -u dnsmasq -n 20"
        info "dnsmasq настроен (слушает: 127.0.0.1, ${_wg_ip})"
    else
        warn "dnsmasq: ошибка конфига — DNS отключён, клиенты будут использовать 8.8.8.8"
    fi
}

# ════════════════════════════════════════════════════════════════
# DNS-РЕЖИМЫ: plain / unbound / dot
# ════════════════════════════════════════════════════════════════

# ── _dns_stop_all — останавливает всё что может занимать DNS ───
_dns_stop_all() {
    # Важно: останавливаем ВСЕ DNS-резолверы — должен работать только один
    # E4: добавлен dnsproxy — без остановки он занимает порт 5053 при смене режима
    systemctl stop dnsmasq  2>/dev/null || true
    systemctl stop stubby   2>/dev/null || true
    systemctl stop unbound  2>/dev/null || true
    systemctl stop dnsproxy 2>/dev/null || true
    systemctl disable stubby   2>/dev/null || true
    systemctl disable unbound  2>/dev/null || true
    systemctl disable dnsmasq  2>/dev/null || true
    systemctl disable dnsproxy 2>/dev/null || true
    # Небольшая пауза чтобы сокеты освободились
    sleep 1
}

# ── _dns_write_dnsmasq — пишет /etc/dnsmasq.d/wg-simple.conf ──
_dns_write_dnsmasq() {
    local _forward="$1"   # строки server=... через \n
    local _wg_ip="${SERVER_IPV4_ADDR%%/*}"

    # Исправление: dnsmasq должен слушать только на WG-интерфейсе и localhost.
    # Если WG-интерфейс ещё не поднят при старте системы — dnsmasq не сможет bind.
    # listen-address=127.0.0.1 всегда доступен, ${_wg_ip} добавляем через bind-interfaces.
    # Директива except-interface=lo исключает петлевой интерфейс от автоматического прослушивания.
    _atomic_write /etc/dnsmasq.d/wg-simple.conf 644 << EOF
# WireGuard Simple Server — dnsmasq (режим: ${DNS_MODE})
# Слушаем только на WG-интерфейсе — защита от Open Resolver
interface=${SERVER_WG_NIC}
bind-dynamic
listen-address=127.0.0.1
listen-address=${_wg_ip}
${_forward}
no-resolv
no-poll
cache-size=1000
log-queries=no
EOF

    # Отключаем resolvconf-интеграцию dnsmasq — она пытается дёргать
    # systemd-resolved которого нет, и мусорит в journalctl
    if [ -f /etc/default/dnsmasq ]; then
        sed -i 's/^#*IGNORE_RESOLVCONF=.*/IGNORE_RESOLVCONF=yes/' /etc/default/dnsmasq
        grep -q '^IGNORE_RESOLVCONF' /etc/default/dnsmasq || \
            echo 'IGNORE_RESOLVCONF=yes' >> /etc/default/dnsmasq
    fi

    # Добавляем ExecStartPre — ждём WG-интерфейс перед стартом dnsmasq
    # Это решает "failed to create listening socket for <WG_IP>: Cannot assign requested address"
    # exit 1 при таймауте — systemd получит ошибку и выполнит Restart=on-failure
    mkdir -p /etc/systemd/system/dnsmasq.service.d
    _atomic_write /etc/systemd/system/dnsmasq.service.d/wg-wait.conf 644 << OVERRIDE
[Service]
ExecStartPre=/bin/sh -c 'for i in 1 2 3 4 5 6 7 8 9 10; do ip addr show ${SERVER_WG_NIC} 2>/dev/null | grep -q "inet " && exit 0; sleep 1; done; exit 1'
OVERRIDE
    systemctl daemon-reload 2>/dev/null || true

    dnsmasq --test 2>/dev/null || { warn "dnsmasq: ошибка конфига"; return 1; }
    systemctl enable --now dnsmasq 2>/dev/null && info "dnsmasq перезапущен (слушает: 127.0.0.1, ${_wg_ip})" || \
        warn "dnsmasq не стартовал — journalctl -u dnsmasq -n 20"
}

# ── _dns_setup_plain ────────────────────────────────────────────
_dns_setup_plain() {
    step "DNS режим: plain (dnsmasq → 1.1.1.1 / 8.8.8.8)"
    _dns_stop_all
    _dns_write_dnsmasq "server=1.1.1.1
server=8.8.8.8"
    DNS_MODE="plain"
    saveConfig
    audit_log "dnsMode plain"
    info "Режим plain активирован"
    hint "DNS-запросы клиентов идут открытым текстом на 1.1.1.1 / 8.8.8.8"
}

# ── _dns_setup_unbound ──────────────────────────────────────────
_dns_setup_unbound() {
    step "DNS режим: Unbound (рекурсивный резолвер)"

    if ! command -v unbound >/dev/null 2>&1; then
        step "Установка unbound..."
        apt-get install -y unbound 2>/dev/null || { warn "unbound: ошибка установки"; return 1; }
    fi

    # Загружаем root hints
    local _hints="/var/lib/unbound/root.hints"
    if [ ! -s "${_hints}" ]; then
        step "Загрузка root.hints..."
        mkdir -p /var/lib/unbound
        if curl -fsSL --max-time 30 -o "${_hints}" \
               "https://www.internic.net/domain/named.cache" 2>/dev/null; then
            info "root.hints загружен"
        else
            warn "Не удалось скачать root.hints — используем встроенный fallback"
            warn "Резолвинг может работать некорректно до следующего обновления root.hints"
            # Минимальный fallback (актуален на 2024–2025, Unbound обновит сам)
            cat > "${_hints}" << 'HINTS'
.                        3600000      NS    A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4
.                        3600000      NS    B.ROOT-SERVERS.NET.
B.ROOT-SERVERS.NET.      3600000      A     170.247.170.2
.                        3600000      NS    C.ROOT-SERVERS.NET.
C.ROOT-SERVERS.NET.      3600000      A     192.33.4.12
HINTS
        fi
    fi

    # Конфиг Unbound — слушает на 127.0.0.1:5335
    _atomic_write /etc/unbound/unbound.conf.d/wg-simple.conf 644 << 'UBCONF'
server:
    verbosity: 0
    interface: 127.0.0.1
    port: 5335
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    root-hints: "/var/lib/unbound/root.hints"
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: yes
    edns-buffer-size: 1472
    prefetch: yes
    num-threads: 1
    so-rcvbuf: 1m
    private-address: 192.168.0.0/16
    private-address: 172.16.0.0/12
    private-address: 10.0.0.0/8
    private-address: fd00::/8
UBCONF

    # AppArmor блокирует unbound (capability net_admin).
    # Переводим профиль в complain-режим или отключаем совсем.
    if command -v aa-status >/dev/null 2>&1; then
        if aa-status --enabled 2>/dev/null; then
            if command -v aa-complain >/dev/null 2>&1; then
                aa-complain /usr/sbin/unbound 2>/dev/null \
                    && info "AppArmor: профиль unbound переведён в complain-режим" \
                    || true
            else
                # aa-complain недоступен — отключаем профиль напрямую
                apparmor_parser -R /etc/apparmor.d/usr.sbin.unbound 2>/dev/null \
                    && info "AppArmor: профиль unbound выгружен" \
                    || true
                mkdir -p /etc/apparmor.d/disable
                ln -sf /etc/apparmor.d/usr.sbin.unbound \
                       /etc/apparmor.d/disable/usr.sbin.unbound 2>/dev/null || true
            fi
        fi
    fi

    systemctl enable unbound 2>/dev/null || true
    if ! systemctl restart unbound 2>/dev/null; then
        warn "unbound не стартовал"
        # Проверяем AppArmor как частую причину
        if command -v aa-status >/dev/null 2>&1 && aa-status --enabled 2>/dev/null; then
            local _aa_denied
            _aa_denied=$(journalctl -u unbound -n 20 --no-pager 2>/dev/null | grep -c 'apparmor.*DENIED' || true)
            if [ "${_aa_denied}" -gt 0 ]; then
                warn "AppArmor блокирует unbound! Установи пакет apparmor-utils и повтори:"
                hint "  apt install apparmor-utils && aa-complain /usr/sbin/unbound"
            else
                hint "journalctl -u unbound -n 30"
            fi
        else
            hint "journalctl -u unbound -n 30"
        fi
        # Не меняем DNS-конфиг — оставляем прежний режим
        warn "DNS-режим не изменён — unbound не запущен"
        return 1
    fi
    info "unbound запущен на 127.0.0.1:5335"

    # dnsmasq форвардит на unbound
    _dns_write_dnsmasq "server=127.0.0.1#5335"

    DNS_MODE="unbound"
    saveConfig
    audit_log "dnsMode unbound"
    info "Режим unbound активирован — запросы клиентов резолвятся рекурсивно, без апстрима"
}

# ── _dns_setup_dot ──────────────────────────────────────────────
_dns_setup_dot() {
    step "DNS режим: DoT (stubby → dnsmasq)"

    if ! command -v stubby >/dev/null 2>&1; then
        step "Установка stubby..."
        apt-get install -y stubby 2>/dev/null || { warn "stubby: ошибка установки"; return 1; }
    fi

    echo ""
    echo -e "  Выбери провайдера DoT (DNS-over-TLS):"
    echo ""
    echo -e "  ${YELLOW} 1${NC}) Cloudflare              1.1.1.1 / 1.0.0.1       (быстрый, no-log)"
    echo -e "  ${YELLOW} 2${NC}) Cloudflare Family        1.1.1.3 / 1.0.0.3       (блокирует малварь+adult)"
    echo -e "  ${YELLOW} 3${NC}) Quad9                   9.9.9.9 / 149.112.112.112 (блокирует малварь, DNSSEC)"
    echo -e "  ${YELLOW} 4${NC}) Quad9 ECS               9.9.9.11                 (с геолокацией)"
    echo -e "  ${YELLOW} 5${NC}) Google                  8.8.8.8 / 8.8.4.4"
    echo -e "  ${YELLOW} 6${NC}) NextDNS                 45.90.28.0 / 45.90.30.0  (настраиваемый)"
    echo -e "  ${YELLOW} 7${NC}) AdGuard DNS              94.140.14.14 / 94.140.15.15 (блокирует рекламу)"
    echo -e "  ${YELLOW} 8${NC}) AdGuard Family           94.140.14.15 / 94.140.15.16 (семейный)"
    echo -e "  ${YELLOW} 9${NC}) CleanBrowsing Security  185.228.168.9 / 185.228.169.9"
    echo -e "  ${YELLOW}10${NC}) CleanBrowsing Family    185.228.168.168 / 185.228.169.168"
    echo -e "  ${YELLOW}11${NC}) OpenDNS                 208.67.222.222 / 208.67.220.220"
    echo -e "  ${YELLOW}12${NC}) OpenDNS FamilyShield    208.67.222.123 / 208.67.220.123"
    echo -e "  ${YELLOW}13${NC}) Comodo Secure           8.26.56.26 / 8.20.247.20"
    echo -e "  ${YELLOW}14${NC}) DNS.Watch               84.200.69.80 / 84.200.70.40  (no-log, Germany)"
    echo -e "  ${YELLOW}15${NC}) Alternate DNS           76.76.19.19 / 76.223.122.150 (без рекламы)"
    echo -e "  ${YELLOW}16${NC}) CIRA Canadian Shield    149.112.121.10 / 149.112.122.10 (Канада)"
    echo -e "  ${YELLOW}17${NC}) Mullvad                 194.242.2.2 / 194.242.2.3    (no-log, Швеция)"
    echo -e "  ${YELLOW}18${NC}) deSEC                   116.203.32.4 / 134.130.36.2  (Германия, DNSSEC)"
    echo -e "  ${YELLOW}19${NC}) Digitale Gesellschaft   185.95.218.42 / 185.95.218.43 (Швейцария)"
    echo -e "  ${YELLOW}20${NC}) DNS0.eu                 193.110.81.0 / 185.253.5.0   (Европа, privacy)"
    echo -e "  ${YELLOW}21${NC}) ВСЕ провайдеры сразу    (round-robin по всем 20)"
    echo ""
    # D1: Поддержка неинтерактивного режима через переменную окружения.
    # Если WG_DOT_PROVIDER задана — пропускаем read и используем её значение.
    # Автоматический запуск без терминала:  WG_DOT_PROVIDER=1 ./wg-for-tunel-dop.sh
    # Через pipe (legacy):                  echo "1" | ./wg-for-tunel-dop.sh
    if [ -n "${WG_DOT_PROVIDER:-}" ]; then
        _dot_choice="${WG_DOT_PROVIDER}"
        hint "WG_DOT_PROVIDER=${_dot_choice} (неинтерактивный режим)"
    else
        read -rp "  Выбор [1]: " _dot_choice
    fi

    # Блоки upstream для каждого провайдера
    local _b1='  - address_data: 1.1.1.1
    tls_auth_name: "cloudflare-dns.com"
  - address_data: 1.0.0.1
    tls_auth_name: "cloudflare-dns.com"'

    local _b2='  - address_data: 1.1.1.3
    tls_auth_name: "cloudflare-dns.com"
  - address_data: 1.0.0.3
    tls_auth_name: "cloudflare-dns.com"'

    local _b3='  - address_data: 9.9.9.9
    tls_auth_name: "dns.quad9.net"
  - address_data: 149.112.112.112
    tls_auth_name: "dns.quad9.net"'

    local _b4='  - address_data: 9.9.9.11
    tls_auth_name: "dns11.quad9.net"'

    local _b5='  - address_data: 8.8.8.8
    tls_auth_name: "dns.google"
  - address_data: 8.8.4.4
    tls_auth_name: "dns.google"'

    local _b6='  - address_data: 45.90.28.0
    tls_auth_name: "dns.nextdns.io"
  - address_data: 45.90.30.0
    tls_auth_name: "dns.nextdns.io"'

    local _b7='  - address_data: 94.140.14.14
    tls_auth_name: "dns.adguard-dns.com"
  - address_data: 94.140.15.15
    tls_auth_name: "dns.adguard-dns.com"'

    local _b8='  - address_data: 94.140.14.15
    tls_auth_name: "family.adguard-dns.com"
  - address_data: 94.140.15.16
    tls_auth_name: "family.adguard-dns.com"'

    local _b9='  - address_data: 185.228.168.9
    tls_auth_name: "security-filter-dns.cleanbrowsing.org"
  - address_data: 185.228.169.9
    tls_auth_name: "security-filter-dns.cleanbrowsing.org"'

    local _b10='  - address_data: 185.228.168.168
    tls_auth_name: "family-filter-dns.cleanbrowsing.org"
  - address_data: 185.228.169.168
    tls_auth_name: "family-filter-dns.cleanbrowsing.org"'

    local _b11='  - address_data: 208.67.222.222
    tls_auth_name: "dns.opendns.com"
  - address_data: 208.67.220.220
    tls_auth_name: "dns.opendns.com"'

    local _b12='  - address_data: 208.67.222.123
    tls_auth_name: "familyshield.opendns.com"
  - address_data: 208.67.220.123
    tls_auth_name: "familyshield.opendns.com"'

    local _b13='  - address_data: 8.26.56.26
    tls_auth_name: "dot.comodo.com"
  - address_data: 8.20.247.20
    tls_auth_name: "dot.comodo.com"'

    local _b14='  - address_data: 84.200.69.80
    tls_auth_name: "resolver1.dns.watch"
  - address_data: 84.200.70.40
    tls_auth_name: "resolver2.dns.watch"'

    local _b15='  - address_data: 76.76.19.19
    tls_auth_name: "freedns.controld.com"
  - address_data: 76.223.122.150
    tls_auth_name: "freedns.controld.com"'

    local _b16='  - address_data: 149.112.121.10
    tls_auth_name: "private.canadianshield.cira.ca"
  - address_data: 149.112.122.10
    tls_auth_name: "private.canadianshield.cira.ca"'

    local _b17='  - address_data: 194.242.2.2
    tls_auth_name: "dns.mullvad.net"
  - address_data: 194.242.2.3
    tls_auth_name: "adblock.dns.mullvad.net"'

    local _b18='  - address_data: 116.203.32.4
    tls_auth_name: "dns2.desec.io"
  - address_data: 134.130.36.2
    tls_auth_name: "dns1.desec.io"'

    local _b19='  - address_data: 185.95.218.42
    tls_auth_name: "dns.digitale-gesellschaft.ch"
  - address_data: 185.95.218.43
    tls_auth_name: "dns.digitale-gesellschaft.ch"'

    local _b20='  - address_data: 193.110.81.0
    tls_auth_name: "dns0.eu"
  - address_data: 185.253.5.0
    tls_auth_name: "dns0.eu"'

    local _dot_provider _upstream_block
    case "${_dot_choice}" in
        2)  _dot_provider="Cloudflare Family";      _upstream_block="${_b2}"  ;;
        3)  _dot_provider="Quad9";                  _upstream_block="${_b3}"  ;;
        4)  _dot_provider="Quad9 ECS";              _upstream_block="${_b4}"  ;;
        5)  _dot_provider="Google";                 _upstream_block="${_b5}"  ;;
        6)  _dot_provider="NextDNS";                _upstream_block="${_b6}"  ;;
        7)  _dot_provider="AdGuard DNS";            _upstream_block="${_b7}"  ;;
        8)  _dot_provider="AdGuard Family";         _upstream_block="${_b8}"  ;;
        9)  _dot_provider="CleanBrowsing Security"; _upstream_block="${_b9}"  ;;
        10) _dot_provider="CleanBrowsing Family";   _upstream_block="${_b10}" ;;
        11) _dot_provider="OpenDNS";                _upstream_block="${_b11}" ;;
        12) _dot_provider="OpenDNS FamilyShield";   _upstream_block="${_b12}" ;;
        13) _dot_provider="Comodo Secure";          _upstream_block="${_b13}" ;;
        14) _dot_provider="DNS.Watch";              _upstream_block="${_b14}" ;;
        15) _dot_provider="Alternate DNS";          _upstream_block="${_b15}" ;;
        16) _dot_provider="CIRA Canadian Shield";   _upstream_block="${_b16}" ;;
        17) _dot_provider="Mullvad";                _upstream_block="${_b17}" ;;
        18) _dot_provider="deSEC";                  _upstream_block="${_b18}" ;;
        19) _dot_provider="Digitale Gesellschaft";  _upstream_block="${_b19}" ;;
        20) _dot_provider="DNS0.eu";                _upstream_block="${_b20}" ;;
        21) _dot_provider="ALL (round-robin 20 провайдеров)"
            _upstream_block="${_b1}
${_b3}
${_b5}
${_b7}
${_b9}
${_b17}
${_b20}
${_b18}
${_b16}
${_b6}" ;;
        *)  _dot_provider="Cloudflare";             _upstream_block="${_b1}"  ;;
    esac

    _atomic_write /etc/stubby/stubby.yml 644 << STUBBYCONF
resolution_type: GETDNS_RESOLUTION_STUB
dns_transport_list:
  - GETDNS_TRANSPORT_TLS
tls_authentication: GETDNS_AUTHENTICATION_REQUIRED
tls_query_padding_blocksize: 128
edns_client_subnet_private: 1
round_robin_upstreams: 1
idle_timeout: 10000
listen_addresses:
  - 127.0.0.1@8053
upstream_recursive_servers:
${_upstream_block}
STUBBYCONF

    systemctl enable stubby 2>/dev/null || true
    if ! systemctl restart stubby 2>/dev/null; then
        warn "stubby не стартовал — journalctl -u stubby -n 20"
        warn "DNS-режим не изменён — stubby не запущен"
        return 1
    fi
    info "stubby запущен (DoT → ${_dot_provider})"

    _dns_write_dnsmasq "server=127.0.0.1#8053"

    DNS_MODE="dot"
    saveConfig
    audit_log "dnsMode dot provider=${_dot_provider}"
    info "Режим DoT активирован — DNS шифруется через TLS (провайдер: ${_dot_provider})"
}


# ── _dns_setup_doh ──────────────────────────────────────────────
# E1: DNS-over-HTTPS через dnsproxy (go-binary от AdGuard).
# Схема: dnsmasq → dnsproxy :5053 → HTTPS-апстрим.
# dnsproxy не требует зависимостей, запускается как systemd-юнит.
_dns_setup_doh() {
    step "DNS режим: DoH (dnsproxy → HTTPS)"

    # ── Установка dnsproxy ────────────────────────────────────────
    local _bin="/usr/local/bin/dnsproxy"
    if [ ! -x "${_bin}" ]; then
        step "Загрузка dnsproxy..."
        local _arch _url _ver="0.73.2"
        _arch=$(uname -m)
        case "${_arch}" in
            x86_64)  _arch="amd64" ;;
            aarch64) _arch="arm64" ;;
            armv7l)  _arch="armv7" ;;
            *)       warn "Архитектура ${_arch} не поддерживается dnsproxy"; return 1 ;;
        esac
        _url="https://github.com/AdguardTeam/dnsproxy/releases/download/v${_ver}/dnsproxy-linux-${_arch}-v${_ver}.tar.gz"
        local _tmp_dir
        _tmp_dir=$(mktemp -d) || { warn "mktemp failed"; return 1; }
        if curl -fsSL --max-time 60 -o "${_tmp_dir}/dnsproxy.tar.gz" "${_url}" 2>/dev/null; then
            tar xzf "${_tmp_dir}/dnsproxy.tar.gz" -C "${_tmp_dir}" 2>/dev/null || true
            local _extracted
            _extracted=$(find "${_tmp_dir}" -name "dnsproxy" -type f | head -1)
            if [ -n "${_extracted}" ]; then
                install -m 755 "${_extracted}" "${_bin}"
                info "dnsproxy установлен: ${_bin}"
            else
                warn "dnsproxy: бинарник не найден в архиве"
                rm -rf "${_tmp_dir}"; return 1
            fi
        else
            warn "Не удалось скачать dnsproxy — проверь интернет или установи вручную"
            warn "URL: ${_url}"
            rm -rf "${_tmp_dir}"; return 1
        fi
        rm -rf "${_tmp_dir}"
    fi

    # ── Выбор провайдера DoH ─────────────────────────────────────
    echo ""
    echo -e "  Выбери провайдера DoH (DNS-over-HTTPS):"
    echo ""
    echo -e "  ${YELLOW}1${NC}) Cloudflare          https://cloudflare-dns.com/dns-query    (быстрый, no-log)"
    echo -e "  ${YELLOW}2${NC}) Cloudflare Family   https://family.cloudflare-dns.com/dns-query (малварь+adult)"
    echo -e "  ${YELLOW}3${NC}) Google              https://dns.google/dns-query"
    echo -e "  ${YELLOW}4${NC}) Quad9               https://dns.quad9.net/dns-query          (малварь, DNSSEC)"
    echo -e "  ${YELLOW}5${NC}) AdGuard DNS         https://dns.adguard-dns.com/dns-query    (без рекламы)"
    echo -e "  ${YELLOW}6${NC}) AdGuard Family      https://family.adguard-dns.com/dns-query (семейный)"
    echo -e "  ${YELLOW}7${NC}) Mullvad             https://dns.mullvad.net/dns-query         (no-log, Швеция)"
    echo -e "  ${YELLOW}8${NC}) NextDNS              https://dns.nextdns.io/dns-query         (настраиваемый)"
    echo -e "  ${YELLOW}9${NC}) ВСЕ сразу            (round-robin по всем 8)"
    echo ""
    # E1/D1: поддержка WG_DOH_PROVIDER для неинтерактивного запуска
    local _doh_choice
    if [ -n "${WG_DOH_PROVIDER:-}" ]; then
        _doh_choice="${WG_DOH_PROVIDER}"
        hint "WG_DOH_PROVIDER=${_doh_choice} (неинтерактивный режим)"
    else
        read -rp "  Выбор [1]: " _doh_choice
    fi

    local _doh_provider _doh_urls
    case "${_doh_choice}" in
        2) _doh_provider="Cloudflare Family"
           _doh_urls="https://family.cloudflare-dns.com/dns-query" ;;
        3) _doh_provider="Google"
           _doh_urls="https://dns.google/dns-query" ;;
        4) _doh_provider="Quad9"
           _doh_urls="https://dns.quad9.net/dns-query" ;;
        5) _doh_provider="AdGuard DNS"
           _doh_urls="https://dns.adguard-dns.com/dns-query" ;;
        6) _doh_provider="AdGuard Family"
           _doh_urls="https://family.adguard-dns.com/dns-query" ;;
        7) _doh_provider="Mullvad"
           _doh_urls="https://dns.mullvad.net/dns-query" ;;
        8) _doh_provider="NextDNS"
           _doh_urls="https://dns.nextdns.io/dns-query" ;;
        9) _doh_provider="ALL (round-robin 8 провайдеров)"
           _doh_urls="https://cloudflare-dns.com/dns-query https://dns.google/dns-query https://dns.quad9.net/dns-query https://dns.adguard-dns.com/dns-query https://dns.mullvad.net/dns-query" ;;
        *) _doh_provider="Cloudflare"
           _doh_urls="https://cloudflare-dns.com/dns-query" ;;
    esac

    # ── Systemd-юнит для dnsproxy ─────────────────────────────────
    # dnsproxy слушает на 127.0.0.1:5053, форвардит по HTTPS
    local _upstream_args=""
    for _u in ${_doh_urls}; do
        _upstream_args+=" --upstream=${_u}"
    done

    _atomic_write /etc/systemd/system/dnsproxy.service 644 << UNITEOF
[Unit]
Description=dnsproxy DNS-over-HTTPS forwarder
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=${_bin} --listen=127.0.0.1:5053 --cache --cache-size=1000${_upstream_args}
Restart=on-failure
RestartSec=5
DynamicUser=yes
CapabilityBoundingSet=
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes

[Install]
WantedBy=multi-user.target
UNITEOF

    systemctl daemon-reload 2>/dev/null || true
    systemctl enable dnsproxy 2>/dev/null || true
    if ! systemctl restart dnsproxy 2>/dev/null; then
        warn "dnsproxy не стартовал — journalctl -u dnsproxy -n 20"
        warn "DNS-режим не изменён"
        return 1
    fi
    info "dnsproxy запущен на 127.0.0.1:5053 (DoH → ${_doh_provider})"

    # dnsmasq форвардит на dnsproxy
    _dns_write_dnsmasq "server=127.0.0.1#5053"

    DNS_MODE="doh"
    saveConfig
    audit_log "dnsMode doh provider=${_doh_provider}"
    info "Режим DoH активирован — DNS шифруется через HTTPS (провайдер: ${_doh_provider})"
}

# ── menuDns ─────────────────────────────────────────────────────
menuDns() {
    loadConfig
    while true; do
        clear
        echo ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   🔐  DNS — только зашифрованные режимы                      ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""

        # Текущий режим
        local _mode_label _mode_color
        case "${DNS_MODE:-plain}" in
            unbound) _mode_label="Unbound (рекурсивный)";     _mode_color="${GREEN}"  ;;
            dot)     _mode_label="DNS-over-TLS (stubby)";     _mode_color="${CYAN}"   ;;
            doh)     _mode_label="DNS-over-HTTPS (dnsproxy)"; _mode_color="${CYAN}"   ;;
            *)       _mode_label="⚠ Plain — НЕБЕЗОПАСНО (смени на DoT/DoH/Unbound)"; _mode_color="${RED}" ;;
        esac
        echo -e "  Текущий режим: ${_mode_color}${BOLD}${_mode_label}${NC}"
        echo ""

        # Статусы сервисов
        local _dns_st _ub_st _st_st _doh_st
        _dns_st=$(_svcStatus "dnsmasq")
        _ub_st=$(_svcStatus "unbound")
        _st_st=$(_svcStatus "stubby")
        _doh_st=$(_svcStatus "dnsproxy")
        echo -e "  dnsmasq: ${_dns_st}   unbound: ${_ub_st}   stubby: ${_st_st}   dnsproxy: ${_doh_st}"

        # Предупреждение если unbound активен но AppArmor его режет
        if [ "${DNS_MODE:-plain}" = "unbound" ]; then
            local _aa_hits
            _aa_hits=$(journalctl -u unbound -n 50 --no-pager 2>/dev/null \
                | grep -c 'apparmor.*DENIED' 2>/dev/null || echo 0)
            if [ "${_aa_hits}" -gt 0 ]; then
                echo -e "  ${RED}⚠  AppArmor блокирует unbound! (DENIED в логах)${NC}"
                echo -e "  ${DIM}Выбери пункт 4 → перезапустить, или вручную:${NC}"
                echo -e "  ${DIM}apt install apparmor-utils && aa-complain /usr/sbin/unbound${NC}"
            fi
        fi
        echo ""
        echo -e "  ${DIM}┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄${NC}"
        echo ""
        echo -e "  ${YELLOW}1${NC})  🔁  ${WHITE}Unbound${NC}   ${DIM}— рекурсивный резолвер, без апстрима, root hints${NC}"
        echo -e "      ${DIM}Сервер сам резолвит. Не доверяет никаким апстримам.${NC}"
        echo ""
        echo -e "  ${YELLOW}2${NC})  🔐  ${WHITE}DoT${NC}       ${DIM}— dnsmasq → stubby → провайдер по TLS (порт 853)${NC}"
        echo -e "      ${DIM}Запросы зашифрованы (TLS 1.3). Провайдер не видит DNS.${NC}"
        echo ""
        echo -e "  ${YELLOW}3${NC})  🌐  ${WHITE}DoH${NC}       ${DIM}— dnsmasq → dnsproxy → провайдер по HTTPS (порт 443)${NC}"
        echo -e "      ${DIM}Работает через стандартный HTTPS — обходит блокировки DNS.${NC}"
        echo ""
        echo -e "  ${RED}  ⚠  Режим Plain (открытый UDP/53) удалён — DNS-запросы должны быть зашифрованы.${NC}"
        echo ""
        echo -e "  ${YELLOW}4${NC})  🔄  Перезапустить текущий DNS-стек"
        echo -e "  ${RED}0${NC})  ←   Назад"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1) _dns_setup_unbound ;;
            2) _dns_setup_dot     ;;
            3) _dns_setup_doh     ;;
            4)
                step "Перезапуск DNS"
                # E2: исправлен fallback (был:-dot, должен быть:-plain) + добавлена ветка doh
                case "${DNS_MODE:-plain}" in
                    unbound) systemctl restart unbound  2>/dev/null && info "unbound перезапущен"  || warn "unbound: ошибка"  ;;
                    dot)     systemctl restart stubby   2>/dev/null && info "stubby перезапущен"   || warn "stubby: ошибка"   ;;
                    doh)     systemctl restart dnsproxy 2>/dev/null && info "dnsproxy перезапущен" || warn "dnsproxy: ошибка" ;;
                esac
                systemctl restart dnsmasq 2>/dev/null && info "dnsmasq перезапущен" || warn "dnsmasq: ошибка"
                ;;
            0) break ;;
            *) warn "Неверный выбор" ;;
        esac
        _pause
    done
}

# ════════════════════════════════════════════════════════════════
# КЛИЕНТЫ
# ════════════════════════════════════════════════════════════════
addClient() {
    loadConfig
    echo -ne "  ${CYAN}→ Имя клиента${NC}: "
    read -r CLIENT_NAME
    [ -z "${CLIENT_NAME}" ] && return
    validateClientName "${CLIENT_NAME}"
    if [ -e "/etc/wireguard/clients/${CLIENT_NAME}.conf" ]; then
        warn "Клиент ${CLIENT_NAME} уже существует"
        return
    fi

    # Автовыдача IP
    local _prefix="${CLIENT_IPV4_SUBNET##*/}"
    if ! [[ "${_prefix}" =~ ^[0-9]+$ ]] || [ "${_prefix}" -lt 16 ] || [ "${_prefix}" -gt 30 ]; then
        warn "CLIENT_IPV4_SUBNET=${CLIENT_IPV4_SUBNET} — поддерживаются префиксы /16../30"
        return
    fi
    local _net="${CLIENT_IPV4_SUBNET%/*}"
    local _o1 _o2 _o3 _o4
    IFS=. read -r _o1 _o2 _o3 _o4 <<< "${_net}"
    # Исправление B1: 10#${} предотвращает интерпретацию октетов с ведущим нулём
    # (напр. 010) как восьмеричных чисел в bash-арифметике.
    _o1=$((10#${_o1})); _o2=$((10#${_o2})); _o3=$((10#${_o3})); _o4=$((10#${_o4}))
    local _net_int=$(( (_o1 << 24) | (_o2 << 16) | (_o3 << 8) | _o4 ))
    local _hosts=$(( (1 << (32 - _prefix)) - 2 ))
    if [ "${_hosts}" -lt 1 ]; then
        warn "Подсеть слишком мала — нет свободных хостов"
        return
    fi

    local _used_file
    _used_file=$(mktemp) || { warn "mktemp failed"; return 1; }
    { awk '/AllowedIPs[[:space:]]*=/{
            for(i=1;i<=NF;i++) if($i ~ /^[0-9.]+\/32([,]|$)/){sub(/\/32.*$/,"",$i); print $i}
        }' "/etc/wireguard/${SERVER_WG_NIC}.conf" 2>/dev/null \
        | awk -F. '{printf "%d\n", ($1*16777216)+($2*65536)+($3*256)+$4}' \
        | sort -un > "${_used_file}"; } || : > "${_used_file}"

    # Читаем занятые IP в ассоциативный массив bash — O(1) поиск вместо grep-процессов
    local _candidate_int=$(( _net_int + 2 ))
    local _max_int=$(( _net_int + _hosts ))
    declare -A _used_map=()
    while IFS= read -r _u; do
        _used_map["${_u}"]=1
    done < "${_used_file}"
    rm -f "${_used_file}"
    while [ "${_candidate_int}" -le "${_max_int}" ] && [ "${_used_map[${_candidate_int}]+x}" ]; do
        _candidate_int=$(( _candidate_int + 1 ))
    done

    if [ "${_candidate_int}" -gt "${_max_int}" ]; then
        warn "Подсеть ${CLIENT_IPV4_SUBNET} заполнена — расширь CLIENT_IPV4_SUBNET"
        return
    fi

    local _c1=$(( (_candidate_int >> 24) & 255 ))
    local _c2=$(( (_candidate_int >> 16) & 255 ))
    local _c3=$(( (_candidate_int >> 8)  & 255 ))
    local _c4=$(( _candidate_int & 255 ))
    local CLIENT_IPV4="${_c1}.${_c2}.${_c3}.${_c4}/32"

    # IPv6 для клиента — только если включён
    local CLIENT_IPV6=""
    if [ "${ENABLE_IPV6:-yes}" = "yes" ] && [ -n "${CLIENT_IPV6_SUBNET:-}" ]; then
        local _v6_id=$(( _candidate_int & 0xFFFF ))
        # Исправление #8: используем python3 для нормализованного формирования IPv6-адреса.
        # Прямое bash-строковое манипулирование ненадёжно для нестандартных форматов (fd66:0:0:1::/64).
        CLIENT_IPV6=$(python3 -c "
import ipaddress, sys
subnet = ipaddress.IPv6Network(sys.argv[1], strict=False)
host_id = int(sys.argv[2])
# Берём сетевой адрес и добавляем смещение хоста
addr = subnet.network_address + host_id
print(str(addr) + '/128')
" "${CLIENT_IPV6_SUBNET}" "${_v6_id}" 2>/dev/null) || {
            warn "Не удалось сформировать IPv6-адрес для клиента — IPv6 будет отключён"
            CLIENT_IPV6=""
        }
    fi

    local PRIV PUB PRE SERVER_PUB_KEY
    PRIV=$(wg genkey)
    [ -n "${PRIV}" ] || error "wg genkey вернул пустой ключ"
    PUB=$(wg pubkey <<< "${PRIV}")
    PRE=$(wg genpsk)
    SERVER_PUB_KEY=$(wg pubkey < /etc/wireguard/server_private.key)

    # DNS: если dnsmasq активен — используем WG-адреса сервера
    # Резолвер всегда 127.0.0.1-based (через dnsmasq), клиентам отдаём WG-IP сервера
    local CLIENT_DNS="1.1.1.1, 8.8.8.8"
    local _wg_ip="${SERVER_IPV4_ADDR%%/*}"
    local _wg_ip6="${SERVER_IPV6_ADDR%%/*}"
    if systemctl is-active dnsmasq >/dev/null 2>&1; then
        if [ "${ENABLE_IPV6:-yes}" = "yes" ] && [ -n "${_wg_ip6:-}" ]; then
            CLIENT_DNS="${_wg_ip}, ${_wg_ip6}"
        else
            CLIENT_DNS="${_wg_ip}"
        fi
    fi

    # ── Выбор режима туннелирования ──────────────────────────────
    echo ""
    echo -e "  ${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "  ${YELLOW}║   🌐  РЕЖИМ МАРШРУТИЗАЦИИ ТРАФИКА                            ║${NC}"
    echo -e "  ${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}Что такое AllowedIPs?${NC}"
    echo -e "  ${DIM}Это список адресов, трафик к которым клиент будет отправлять${NC}"
    echo -e "  ${DIM}через VPN-туннель. Всё остальное пойдёт напрямую в интернет.${NC}"
    echo ""
    echo -e "  ${YELLOW}1${NC})  🔒  ${WHITE}Full-tunnel${NC}  ${DIM}(рекомендуется для анонимности и безопасности)${NC}"
    echo ""
    echo -e "      ${DIM}AllowedIPs = 0.0.0.0/0${CLIENT_IPV6:+, ::/0}${NC}"
    echo -e "      ${DIM}Весь интернет-трафик клиента идёт через твой VPN-сервер.${NC}"
    echo -e "      ${DIM}Провайдер клиента не видит ни один сайт — видит только${NC}"
    echo -e "      ${DIM}одно зашифрованное соединение с твоим сервером.${NC}"
    echo -e "      ${DIM}DNS-запросы тоже идут через сервер (зашифрованный DoT).${NC}"
    echo -e "      ${DIM}Минус: весь трафик нагружает канал сервера.${NC}"
    echo ""
    echo -e "  ${YELLOW}2${NC})  🔀  ${WHITE}Split-tunnel${NC}  ${DIM}(только VPN-сеть, интернет напрямую)${NC}"
    echo ""
    local _wg_net4="${CLIENT_IPV4_SUBNET}"
    local _wg_net6="${CLIENT_IPV6_SUBNET:-}"
    local _split_hint="${_wg_net4}"
    [ -n "${CLIENT_IPV6}" ] && _split_hint="${_wg_net4}, ${_wg_net6}"
    echo -e "      ${DIM}AllowedIPs = ${_split_hint}${NC}"
    echo -e "      ${DIM}Через VPN идёт только трафик внутри VPN-сети.${NC}"
    echo -e "      ${DIM}Клиенты видят друг друга и сервер, но интернет${NC}"
    echo -e "      ${DIM}они открывают через свой обычный провайдер — быстрее,${NC}"
    echo -e "      ${DIM}но IP клиента в интернете остаётся его настоящим IP.${NC}"
    echo -e "      ${DIM}Используется для корпоративных сетей или доступа к${NC}"
    echo -e "      ${DIM}ресурсам внутри VPN без «проксирования» всего трафика.${NC}"
    echo ""
    echo -e "  ${YELLOW}3${NC})  ✏️   ${WHITE}Свой список CIDR${NC}  ${DIM}(для опытных пользователей)${NC}"
    echo ""
    echo -e "      ${DIM}Ты сам вводишь список адресов через запятую.${NC}"
    echo -e "      ${DIM}Пример: 0.0.0.0/0 — весь трафик через VPN.${NC}"
    echo -e "      ${DIM}Пример: 10.0.0.0/8, 192.168.0.0/16 — только локальные.${NC}"
    echo -e "      ${DIM}Пример: 0.0.0.0/0, !192.168.1.0/24 — всё кроме домашней сети${NC}"
    echo -e "      ${DIM}(исключения поддерживаются только в приложении WG на ПК/Android).${NC}"
    echo ""
    read -rp "  Выбор [1]: " _tunnel_mode
    [ -z "${_tunnel_mode}" ] && _tunnel_mode="1"

    local _client_allowed_ips
    case "${_tunnel_mode}" in
        2)
            _client_allowed_ips="${_wg_net4}"
            [ -n "${CLIENT_IPV6}" ] && [ -n "${_wg_net6}" ] && \
                _client_allowed_ips="${_wg_net4}, ${_wg_net6}"
            info "Split-tunnel: трафик внутри VPN-сети (${_client_allowed_ips})"
            ;;
        3)
            echo ""
            echo -e "  ${DIM}Введи AllowedIPs через запятую (например: 0.0.0.0/0 или 10.0.0.0/8, 172.16.0.0/12):${NC}"
            echo -ne "  ${CYAN}→ AllowedIPs${NC}: "
            _WG_INTERACTIVE=1; read -r _client_allowed_ips; _WG_INTERACTIVE=0
            if [ -z "${_client_allowed_ips}" ]; then
                warn "Пусто — используем Full-tunnel (0.0.0.0/0)"
                _client_allowed_ips="0.0.0.0/0"
                [ -n "${CLIENT_IPV6}" ] && _client_allowed_ips="0.0.0.0/0, ::/0"
            else
                # Валидируем каждый CIDR
                local _raw_ips _ok=1
                IFS=',' read -ra _raw_ips <<< "${_client_allowed_ips}"
                for _cidr in "${_raw_ips[@]}"; do
                    _cidr="${_cidr// /}"
                    # Пропускаем исключения (начинаются с !)
                    [[ "${_cidr}" == !* ]] && continue
                    if ! python3 -c "
import ipaddress, sys
try:
    ipaddress.ip_network(sys.argv[1], strict=False)
except ValueError:
    sys.exit(1)
" "${_cidr}" 2>/dev/null; then
                        warn "Неверный CIDR: '${_cidr}' — проверь формат"
                        _ok=0
                    fi
                done
                if [ "${_ok}" -eq 0 ]; then
                    warn "Есть ошибки в CIDR — используем Full-tunnel (0.0.0.0/0)"
                    _client_allowed_ips="0.0.0.0/0"
                    [ -n "${CLIENT_IPV6}" ] && _client_allowed_ips="0.0.0.0/0, ::/0"
                fi
            fi
            info "Свой список: ${_client_allowed_ips}"
            ;;
        *)
            _client_allowed_ips="0.0.0.0/0"
            [ -n "${CLIENT_IPV6}" ] && _client_allowed_ips="0.0.0.0/0, ::/0"
            info "Full-tunnel: весь трафик через VPN"
            ;;
    esac

    # Строим строки AllowedIPs и Address с учётом IPv6
    local _server_allowed_ips="${CLIENT_IPV4}"
    local _client_address="${CLIENT_IPV4}"
    if [ -n "${CLIENT_IPV6}" ]; then
        _server_allowed_ips="${CLIENT_IPV4}, ${CLIENT_IPV6}"
        _client_address="${CLIENT_IPV4}, ${CLIENT_IPV6}"
    fi

    # Добавляем пира в серверный конфиг атомарно (защита от частичной записи)
    local _sconf="/etc/wireguard/${SERVER_WG_NIC}.conf"
    local _existing_conf=""
    [ -f "${_sconf}" ] && _existing_conf=$(cat "${_sconf}")
    printf '%s\n\n[Peer]\n# %s\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s\n' \
        "${_existing_conf}" "${CLIENT_NAME}" "${PUB}" "${PRE}" "${_server_allowed_ips}" \
        | _atomic_write "${_sconf}" 600

    # Создаём клиентский конфиг
    mkdir -p /etc/wireguard/clients
    (umask 077; cat > "/etc/wireguard/clients/${CLIENT_NAME}.conf" << EOF
[Interface]
PrivateKey = ${PRIV}
Address = ${_client_address}
DNS = ${CLIENT_DNS}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${PRE}
Endpoint = ${SERVER_PUB_IP}:${SERVER_PORT}
AllowedIPs = ${_client_allowed_ips}
PersistentKeepalive = 25
EOF
)

    # Улучшение #1: временный файл вместо /dev/stdin.
    # wg < 1.0.20200513 не умеет читать preshared-key из /dev/stdin,
    # временный файл работает на всех версиях. umask 077 — ключ недоступен другим.
    local _psk_tmp
    _psk_tmp=$(umask 077; mktemp) && {
        printf '%s
' "${PRE}" > "${_psk_tmp}"
        wg set "${SERVER_WG_NIC}" peer "${PUB}" \
            preshared-key "${_psk_tmp}" \
            allowed-ips "${_server_allowed_ips// /}" 2>/dev/null || true
        rm -f "${_psk_tmp}"
    } || warn "addClient: не удалось создать временный файл PSK — пир добавлен без live-обновления"

    # QR-код
    qrencode -o "/etc/wireguard/clients/${CLIENT_NAME}.png" -t PNG \
        < "/etc/wireguard/clients/${CLIENT_NAME}.conf" 2>/dev/null || true

    info "Клиент ${GREEN}${CLIENT_NAME}${NC} добавлен (IP: ${CLIENT_IPV4}${CLIENT_IPV6:+, ${CLIENT_IPV6}}, DNS: ${CLIENT_DNS})"
    audit_log "addClient name=${CLIENT_NAME} ip=${CLIENT_IPV4}"
    echo ""
    echo -e "  ${YELLOW}QR-код для импорта в приложение WireGuard:${NC}"
    echo ""
    qrencode -t UTF8 < "/etc/wireguard/clients/${CLIENT_NAME}.conf" 2>/dev/null || \
        warn "qrencode не установлен — QR не показан, конфиг: /etc/wireguard/clients/${CLIENT_NAME}.conf"
    echo ""
    hint "Конфиг: /etc/wireguard/clients/${CLIENT_NAME}.conf"
    hint "QR PNG:  /etc/wireguard/clients/${CLIENT_NAME}.png"
}

listClients() {
    loadConfig
    step "Список клиентов"
    shopt -s nullglob
    local _cf=(/etc/wireguard/clients/*.conf)
    shopt -u nullglob
    if [ ! -d /etc/wireguard/clients ] || [ "${#_cf[@]}" -eq 0 ]; then
        warn "Нет клиентов"
        return
    fi
    echo ""
    printf "  ${BOLD}${CYAN}  %-20s  %-20s  %-22s  %-16s${NC}\n" "Имя" "IPv4" "IPv6" "Последний online"
    echo -e "  ${CYAN}────────────────────────────────────────────────────────────────────────────${NC}"
    for f in /etc/wireguard/clients/*.conf; do
        local name ipv4 ipv6 last_hs
        name=$(basename "${f}" .conf)
        ipv4=$(awk -F'=' '/^[[:space:]]*Address[[:space:]]*=/{split($2,a,","); gsub(/[[:space:]]/,"",a[1]); print a[1]; exit}' "${f}")
        ipv6=$(awk -F'=' '/^[[:space:]]*Address[[:space:]]*=/{split($2,a,","); gsub(/[[:space:]]/,"",a[2]); print a[2]; exit}' "${f}")
        # Последний handshake из wg show
        local _pub
        _pub=$(awk -F'=' '/^[[:space:]]*PrivateKey[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "${f}" | wg pubkey 2>/dev/null || echo "")
        if [ -n "${_pub}" ]; then
            last_hs=$(wg show "${SERVER_WG_NIC}" latest-handshakes 2>/dev/null | awk -v pub="${_pub}" '$1==pub{print $2}')
            if [ -n "${last_hs}" ] && [ "${last_hs}" != "0" ]; then
                local _now _diff
                _now=$(date +%s)
                _diff=$(( _now - last_hs ))
                if [ "${_diff}" -lt 180 ]; then
                    last_hs="${GREEN}online${NC}"
                elif [ "${_diff}" -lt 3600 ]; then
                    last_hs="${YELLOW}$(( _diff / 60 ))м назад${NC}"
                elif [ "${_diff}" -lt 86400 ]; then
                    last_hs="${DIM}$(( _diff / 3600 ))ч назад${NC}"
                else
                    last_hs="${DIM}$(( _diff / 86400 ))д назад${NC}"
                fi
            else
                last_hs="${DIM}никогда${NC}"
            fi
        else
            last_hs="${DIM}—${NC}"
        fi
        printf "  ${GREEN}  %-20s${NC}  %-20s  %-22s  " "${name}" "${ipv4}" "${ipv6:-—}"
        echo -e "${last_hs}"
    done
    echo ""
}

showClientQR() {
    loadConfig
    listClients
    echo -ne "  ${CYAN}→ Имя клиента для QR-кода${NC}: "
    read -r CLIENT_NAME
    [ -z "${CLIENT_NAME}" ] && return
    local CLIENT_CONF="/etc/wireguard/clients/${CLIENT_NAME}.conf"
    [ ! -f "${CLIENT_CONF}" ] && { warn "Клиент не найден"; return; }
    echo ""
    echo -e "  ${YELLOW}QR-код для ${CLIENT_NAME}:${NC}"
    echo ""
    qrencode -t UTF8 < "${CLIENT_CONF}" 2>/dev/null || \
        warn "qrencode не установлен"
    echo ""
    hint "Конфиг: ${CLIENT_CONF}"
    hint "PNG:    ${CLIENT_CONF%.conf}.png"
}

revokeClient() {
    loadConfig
    listClients
    echo -ne "  ${CYAN}→ Имя клиента для отзыва${NC}: "
    read -r CLIENT_NAME
    [ -z "${CLIENT_NAME}" ] && return
    local CLIENT_CONF="/etc/wireguard/clients/${CLIENT_NAME}.conf"
    [ ! -f "${CLIENT_CONF}" ] && { warn "Клиент не найден"; return; }

    local CLIENT_PRIV PUB
    CLIENT_PRIV=$(awk -F'=' '/^[[:space:]]*PrivateKey[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "${CLIENT_CONF}")
    [ -z "${CLIENT_PRIV}" ] && { warn "Не найден PrivateKey в конфиге клиента"; return; }
    PUB=$(wg pubkey <<< "${CLIENT_PRIV}" 2>/dev/null) || { warn "Невалидный PrivateKey"; return; }

    # Удаляем блок [Peer] из серверного конфига
    python3 - "${PUB}" "/etc/wireguard/${SERVER_WG_NIC}.conf" << 'PYEOF'         || { warn "Ошибка удаления пира из конфига — пир может появиться после перезапуска WG"; return 1; }
import sys, re
pub, path = sys.argv[1], sys.argv[2]
try:
    with open(path) as f:
        data = f.read().replace('\r\n', '\n').replace('\r', '\n')
except FileNotFoundError:
    sys.exit(0)
parts = re.split(r'(?m)^(?=[ \t]*\[Peer\][ \t]*$)', data)
out = [p for p in parts
       if not (p.lstrip().startswith('[Peer]')
               and re.search(r'(?m)^\s*PublicKey\s*=\s*' + re.escape(pub) + r'\s*$', p))]
with open(path, 'w') as f:
    f.write(''.join(out))
print("ok")
PYEOF

    wg set "${SERVER_WG_NIC}" peer "${PUB}" remove 2>/dev/null || true
    rm -f "${CLIENT_CONF}" "/etc/wireguard/clients/${CLIENT_NAME}.png"
    info "Клиент ${CLIENT_NAME} отозван"
    audit_log "revokeClient name=${CLIENT_NAME}"
}

# ════════════════════════════════════════════════════════════════
# СТАТУС
# ════════════════════════════════════════════════════════════════
_clientCount() {
    if [ -d /etc/wireguard/clients ]; then
        shopt -s nullglob
        local _f=(/etc/wireguard/clients/*.conf)
        shopt -u nullglob
        echo "${#_f[@]}"
    else
        echo 0
    fi
}

_svcStatus() {
    systemctl is-active "${1}" 2>/dev/null | grep -q "^active$" \
        && echo -e "${GREEN}●${NC}" || echo -e "${RED}○${NC}"
}

_statusBar() {
    [ -z "${SERVER_WG_NIC:-}" ] && loadConfig
    local wg_st nft_st dns_st clients
    wg show "${SERVER_WG_NIC:-wg0}" >/dev/null 2>&1 \
        && wg_st="${GREEN}UP${NC}" || wg_st="${RED}DOWN${NC}"
    nft_st=$(_svcStatus "nftables")
    dns_st=$(_svcStatus "dnsmasq")
    clients=$(_clientCount)

    local _dns_mode_short
    case "${DNS_MODE:-plain}" in
        unbound) _dns_mode_short="${GREEN}unbound${NC}" ;;
        dot)     _dns_mode_short="${CYAN}DoT${NC}"      ;;
        doh)     _dns_mode_short="${CYAN}DoH${NC}"      ;;
        *)       _dns_mode_short="${RED}plain⚠${NC}"    ;;
    esac

    local _addr_part=""
    if [ -n "${SERVER_PUB_IP:-}" ] && [ -n "${SERVER_PORT:-}" ]; then
        _addr_part="  ${DIM}${SERVER_PUB_IP}:${SERVER_PORT}${NC}"
    fi

    echo -e "  ${DIM}┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄${NC}"
    echo -e "  ${WHITE}WG${NC}: ${wg_st}  ${WHITE}NFT${NC}: ${nft_st}  ${WHITE}DNS${NC}: ${dns_st} [${_dns_mode_short}]  ${WHITE}Клиентов${NC}: ${GREEN}${clients}${NC}${_addr_part}"
    echo -e "  ${DIM}┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄${NC}"
}

menuWGStatus() {
    step "Статус WireGuard"
    echo ""
    wg show 2>/dev/null || warn "WireGuard не запущен"
    echo ""
    step "Подключённые пиры (last handshake)"
    wg show "${SERVER_WG_NIC}" latest-handshakes 2>/dev/null | while IFS=$'\t' read -r pub ts; do
        local _name="—"
        # Ищем имя клиента по публичному ключу
        if [ -d /etc/wireguard/clients ]; then
            for f in /etc/wireguard/clients/*.conf; do
                [ -f "${f}" ] || continue
                local _priv
                _priv=$(awk -F'=' '/^[[:space:]]*PrivateKey[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "${f}" 2>/dev/null)
                [ -z "${_priv}" ] && continue
                local _p
                _p=$(wg pubkey <<< "${_priv}" 2>/dev/null)
                if [ "${_p}" = "${pub}" ]; then
                    _name=$(basename "${f}" .conf)
                    break
                fi
            done
        fi
        local _ago="никогда"
        if [ -n "${ts}" ] && [ "${ts}" != "0" ]; then
            local _diff=$(( $(date +%s) - ts ))
            if [ "${_diff}" -lt 180 ]; then _ago="online"
            elif [ "${_diff}" -lt 3600 ]; then _ago="$(( _diff / 60 ))м назад"
            else _ago="$(( _diff / 3600 ))ч назад"; fi
        fi
        printf "  ${GREEN}%-18s${NC}  ${DIM}%s${NC}  ${CYAN}%s${NC}\n" "${_name}" "${pub:0:20}..." "${_ago}"
    done || true
    echo ""
    step "Трафик пиров"
    wg show "${SERVER_WG_NIC}" transfer 2>/dev/null | \
        awk '{printf "  %-44s  rx: %7.1f МБ  tx: %7.1f МБ\n", $1, $2/1048576, $3/1048576}' || true

    echo ""
    step "DNS"
    local _wg_ip="${SERVER_IPV4_ADDR%%/*}"
    local _mode_label
    case "${DNS_MODE:-plain}" in
        unbound) _mode_label="${GREEN}Unbound${NC} — рекурсивный резолвер (root hints, без апстрима)" ;;
        dot)     _mode_label="${CYAN}DNS-over-TLS${NC} — stubby шифрует запросы к апстриму" ;;
        doh)     _mode_label="${CYAN}DNS-over-HTTPS${NC} — dnsproxy форвардит по HTTPS" ;;
        *)       _mode_label="${RED}⚠ Plain${NC} — открытый UDP/53 (НЕБЕЗОПАСНО — смени на DoT/DoH/Unbound)" ;;
    esac
    echo -e "  Режим: ${_mode_label}"
    echo -e "  DNS для клиентов: ${CYAN}${_wg_ip:-н/д}${NC}"
    # Краткая проверка резолвинга
    local _resolve_ok=0
    if command -v dig >/dev/null 2>&1; then
        dig +short +time=2 +tries=1 @"${_wg_ip}" cloudflare.com >/dev/null 2>&1 && _resolve_ok=1
    elif command -v nslookup >/dev/null 2>&1; then
        nslookup -timeout=2 cloudflare.com "${_wg_ip}" >/dev/null 2>&1 && _resolve_ok=1
    fi
    if [ "${_resolve_ok}" -eq 1 ]; then
        echo -e "  Тест резолвинга: ${GREEN}✔ OK${NC}  (${_wg_ip} отвечает)"
    else
        echo -e "  Тест резолвинга: ${RED}✗ нет ответа${NC}  (dnsmasq не запущен или ${_wg_ip} недоступен)"
    fi
    case "${DNS_MODE:-plain}" in
        unbound)
            systemctl is-active unbound >/dev/null 2>&1 \
                && echo -e "  unbound:  ${GREEN}● активен${NC}" \
                || echo -e "  unbound:  ${RED}○ не запущен${NC}"
            ;;
        dot)
            systemctl is-active stubby >/dev/null 2>&1 \
                && echo -e "  stubby:   ${GREEN}● активен${NC}" \
                || echo -e "  stubby:   ${RED}○ не запущен${NC}"
            ;;
        doh)
            systemctl is-active dnsproxy >/dev/null 2>&1 \
                && echo -e "  dnsproxy: ${GREEN}● активен${NC}" \
                || echo -e "  dnsproxy: ${RED}○ не запущен${NC}"
            ;;
    esac
    systemctl is-active dnsmasq >/dev/null 2>&1 \
        && echo -e "  dnsmasq: ${GREEN}● активен${NC}" \
        || echo -e "  dnsmasq: ${RED}○ не запущен${NC}"
}

menuLogs() {
    while true; do
        clear
        echo ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   📄  ЛОГИ                                                   ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${YELLOW}1${NC})  🔐  WireGuard (systemctl / wg show)"
        echo -e "  ${YELLOW}2${NC})  🌐  dnsmasq (DNS)"
        echo -e "  ${YELLOW}3${NC})  🔥  nftables"
        echo -e "  ${YELLOW}4${NC})  📋  Аудит действий"
        echo -e "  ${YELLOW}5${NC})  ⚙   Системный журнал (kernel/network)"
        echo -e "  ${RED}0${NC})  ←   Назад"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1) journalctl -u "wg-quick@${SERVER_WG_NIC}" -n 40 --no-pager 2>/dev/null || \
                   wg show 2>/dev/null || warn "WG не запущен" ;;
            2) journalctl -u dnsmasq -n 40 --no-pager 2>/dev/null || warn "dnsmasq не запущен" ;;
            3) journalctl -u nftables -n 20 --no-pager 2>/dev/null; echo ""; nft list ruleset 2>/dev/null | head -40 ;;
            4) [ -f "${_AUDIT_LOG}" ] && tail -40 "${_AUDIT_LOG}" || warn "Лог пустой" ;;
            5) journalctl -k -n 30 --no-pager 2>/dev/null ;;
            0) break ;;
            *) warn "Неверный выбор" ;;
        esac
        _pause
    done
}

# ════════════════════════════════════════════════════════════════
# БЭКАП / ВОССТАНОВЛЕНИЕ
# ════════════════════════════════════════════════════════════════
backupConfig() {
    step "Создание бэкапа"
    local _dir="/var/backups/wg-simple"
    local _ts _file
    _ts=$(date +%Y%m%d-%H%M%S)
    _file="${_dir}/backup-${_ts}.tar.gz"
    mkdir -p "${_dir}"
    local _list=()
    local _p
    for _p in /etc/wireguard /etc/nftables.conf /etc/dnsmasq.d/wg-simple.conf \
               /etc/sysctl.d/99-wg-simple.conf /etc/sysctl.d/99-wg-hardening.conf \
               "/etc/systemd/system/wg-quick@${SERVER_WG_NIC}.service.d"; do
        [ -e "${_p}" ] && _list+=("${_p}")
    done
    if tar czf "${_file}" "${_list[@]}" 2>/dev/null; then
        info "Бэкап: ${_file}"
        find "${_dir}" -maxdepth 1 -name "backup-*.tar.gz" | sort -r | tail -n +11 | xargs -r rm -f
    else
        warn "Ошибка создания бэкапа"
        return 1
    fi
}

restoreConfig() {
    step "Восстановление из бэкапа"
    local _dir="/var/backups/wg-simple"
    [ -d "${_dir}" ] || { warn "Директория бэкапов не найдена: ${_dir}"; return; }
    echo ""
    find "${_dir}" -maxdepth 1 -name "backup-*.tar.gz" -printf "%T@ %p\n" 2>/dev/null \
        | sort -rn | head -10 | awk '{print "  " NR") " $2}' || \
        { warn "Бэкапов нет"; return; }
    echo ""
    read -rp "  Введи имя файла (полный путь): " _bfile
    [ -z "${_bfile}" ] && return
    # Исправление A8: ограничиваем путь каталогом бэкапов —
    # предотвращает случайную распаковку произвольного архива в /
    if [[ "${_bfile}" != "${_dir}/"* ]]; then
        warn "Файл должен находиться в ${_dir}/"
        return
    fi
    [ ! -f "${_bfile}" ] && { warn "Файл не найден: ${_bfile}"; return; }
    local _confirm
    askYesNo "Восстановить из ${_bfile}? Текущие конфиги будут перезаписаны!" "_confirm" "n"
    [ "${_confirm}" != "yes" ] && { info "Отменено"; return; }
    tar xzf "${_bfile}" -C / 2>/dev/null && info "Восстановлено из ${_bfile}" || \
        warn "Ошибка восстановления"
}

menuBackup() {
    while true; do
        clear
        echo ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   💾  БЭКАП / ВОССТАНОВЛЕНИЕ                                 ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${YELLOW}1${NC})  💾  Создать бэкап сейчас"
        echo -e "  ${YELLOW}2${NC})  ♻️   Восстановить из бэкапа"
        echo -e "  ${YELLOW}3${NC})  📋  Список бэкапов"
        echo -e "  ${RED}0${NC})  ←   Назад"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1) backupConfig ;;
            2) restoreConfig ;;
            3) find /var/backups/wg-simple -maxdepth 1 -name "backup-*.tar.gz" -printf "%s %p\n" 2>/dev/null \
                   | sort -rn | awk '{printf "  %s  (%.1f KB)\n", $2, $1/1024}' || warn "Бэкапов нет" ;;
            0) break ;;
            *) warn "Неверный выбор" ;;
        esac
        _pause
    done
}

# ════════════════════════════════════════════════════════════════
# АВТОЗАПУСК
# ════════════════════════════════════════════════════════════════
menuAutostart() {
    loadConfig
    while true; do
        clear
        echo ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   🚀  АВТОЗАПУСК СЕРВИСОВ                                    ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        local _wg_en _nft_en _dns_en _ub_en _st_en
        systemctl is-enabled "wg-quick@${SERVER_WG_NIC}" 2>/dev/null | grep -q enabled \
            && _wg_en="${GREEN}включён${NC}" || _wg_en="${RED}выключен${NC}"
        systemctl is-enabled nftables 2>/dev/null | grep -q enabled \
            && _nft_en="${GREEN}включён${NC}" || _nft_en="${RED}выключен${NC}"
        systemctl is-enabled dnsmasq 2>/dev/null | grep -q enabled \
            && _dns_en="${GREEN}включён${NC}" || _dns_en="${RED}выключен${NC}"
        systemctl is-enabled unbound 2>/dev/null | grep -q enabled \
            && _ub_en="${GREEN}включён${NC}" || _ub_en="${DIM}н/д${NC}"
        systemctl is-enabled stubby 2>/dev/null | grep -q enabled \
            && _st_en="${GREEN}включён${NC}" || _st_en="${DIM}н/д${NC}"
        printf "  WireGuard (wg-quick@%s):  " "${SERVER_WG_NIC}"; echo -e "${_wg_en}"
        printf "  nftables:                  "; echo -e "${_nft_en}"
        printf "  dnsmasq:                   "; echo -e "${_dns_en}"
        # E6: добавлена ветка doh
        local _dp_en
        systemctl is-enabled dnsproxy 2>/dev/null | grep -q enabled \
            && _dp_en="${GREEN}включён${NC}" || _dp_en="${DIM}н/д${NC}"
        case "${DNS_MODE:-plain}" in
            unbound) printf "  unbound:                   "; echo -e "${_ub_en}" ;;
            dot)     printf "  stubby (DoT):              "; echo -e "${_st_en}" ;;
            doh)     printf "  dnsproxy (DoH):            "; echo -e "${_dp_en}" ;;
        esac
        echo ""
        echo -e "  ${YELLOW}1${NC})  ✅  Включить автозапуск всех"
        echo -e "  ${YELLOW}2${NC})  ❌  Выключить автозапуск всех"
        echo -e "  ${YELLOW}3${NC})  🔄  Перезапустить все сервисы сейчас"
        echo -e "  ${RED}0${NC})  ←   Назад"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1)
                systemctl enable nftables 2>/dev/null && info "nftables: автозапуск включён" || warn "nftables: ошибка"
                systemctl enable "wg-quick@${SERVER_WG_NIC}" 2>/dev/null && info "WG: автозапуск включён" || warn "WG: ошибка"
                systemctl enable dnsmasq 2>/dev/null && info "dnsmasq: автозапуск включён" || warn "dnsmasq: ошибка"
                # E6: добавлена ветка doh
                case "${DNS_MODE:-plain}" in
                    unbound) systemctl enable unbound  2>/dev/null && info "unbound: автозапуск включён"  || warn "unbound: ошибка"  ;;
                    dot)     systemctl enable stubby   2>/dev/null && info "stubby: автозапуск включён"   || warn "stubby: ошибка"   ;;
                    doh)     systemctl enable dnsproxy 2>/dev/null && info "dnsproxy: автозапуск включён" || warn "dnsproxy: ошибка" ;;
                esac
                audit_log "autostart enable"
                ;;
            2)
                systemctl disable nftables  2>/dev/null || true
                systemctl disable "wg-quick@${SERVER_WG_NIC}" 2>/dev/null || true
                systemctl disable dnsmasq   2>/dev/null || true
                systemctl disable unbound   2>/dev/null || true
                systemctl disable stubby    2>/dev/null || true
                systemctl disable dnsproxy  2>/dev/null || true  # E6
                audit_log "autostart disable"
                info "Автозапуск отключён"
                ;;
            3)
                step "Перезапуск сервисов"
                systemctl restart nftables 2>/dev/null || warn "nftables: ошибка"
                wg-quick down "${SERVER_WG_NIC}" 2>/dev/null || true
                sleep 1
                wg-quick up "${SERVER_WG_NIC}" 2>/dev/null && info "WG поднят" || warn "WG не поднялся"
                # E6: добавлена ветка doh
                case "${DNS_MODE:-plain}" in
                    unbound) systemctl restart unbound  2>/dev/null && info "unbound перезапущен"  || warn "unbound: ошибка"  ;;
                    dot)     systemctl restart stubby   2>/dev/null && info "stubby перезапущен"   || warn "stubby: ошибка"   ;;
                    doh)     systemctl restart dnsproxy 2>/dev/null && info "dnsproxy перезапущен" || warn "dnsproxy: ошибка" ;;
                esac
                systemctl restart dnsmasq 2>/dev/null && info "dnsmasq перезапущен" || warn "dnsmasq: ошибка"
                ;;
            0) break ;;
            *) warn "Неверный выбор" ;;
        esac
        _pause
    done
}

# ════════════════════════════════════════════════════════════════
# ПОЛНОЕ УДАЛЕНИЕ
# ════════════════════════════════════════════════════════════════
removeAll() {
    # Исправление: загружаем конфиг ДО любых действий, чтобы SERVER_WG_NIC не был пустым
    loadConfig
    [ -z "${SERVER_WG_NIC:-}" ] && {
        warn "SERVER_WG_NIC не определён — пытаюсь определить из /etc/wireguard/*.conf"
        SERVER_WG_NIC=$(find /etc/wireguard -maxdepth 1 -name '*.conf' \
            ! -name '.wg-simple.conf' 2>/dev/null | head -1 | xargs -r basename -s .conf)
        [ -z "${SERVER_WG_NIC}" ] && SERVER_WG_NIC="wg0"
        warn "Используем SERVER_WG_NIC=${SERVER_WG_NIC}"
    }

    echo ""
    echo -e "${RED}${BOLD}  ╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}${BOLD}  ║        ⚠  ПОЛНОЕ УДАЛЕНИЕ WIREGUARD  ⚠           ║${NC}"
    echo -e "${RED}${BOLD}  ╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${YELLOW}Это действие необратимо! Для подтверждения введи: ${BOLD}REMOVE${NC}"
    echo ""
    read -rp "  Ввод: " CONFIRM
    if [ "${CONFIRM}" != "REMOVE" ]; then
        warn "Отменено"; return
    fi

    _autoBackup "remove-all" || warn "Бэкап не создан — продолжаем"

    step "Остановка сервисов"
    for iface in $(wg show interfaces 2>/dev/null); do
        wg-quick down "${iface}" 2>/dev/null || true
    done
    # E5: добавлен dnsproxy
    systemctl stop nftables dnsmasq unbound stubby dnsproxy 2>/dev/null || true
    systemctl disable nftables dnsmasq unbound stubby dnsproxy 2>/dev/null || true
    [ -n "${SERVER_WG_NIC:-}" ] && systemctl disable "wg-quick@${SERVER_WG_NIC}" 2>/dev/null || true

    step "Очистка nftables"
    nft delete table inet "wg-simple-filter-${SERVER_WG_NIC}" 2>/dev/null || true
    nft delete table inet "wg-simple-nat-${SERVER_WG_NIC}"    2>/dev/null || true
    # Исправление #6: удаляем IPv6 NAT-таблицу (тип ip6, не inet)
    nft delete table ip6  "wg-simple-nat6-${SERVER_WG_NIC}"   2>/dev/null || true
    # Обратная совместимость со старыми именами
    nft delete table inet wg-simple-filter 2>/dev/null || true
    nft delete table inet wg-simple-nat    2>/dev/null || true
    rm -f /etc/nftables.conf

    step "Удаление systemd override"
    [ -n "${SERVER_WG_NIC:-}" ] && \
        rm -rf "/etc/systemd/system/wg-quick@${SERVER_WG_NIC}.service.d"
    rm -f /etc/systemd/system/dnsmasq.service.d/wg-wait.conf
    rmdir /etc/systemd/system/dnsmasq.service.d 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true

    step "Удаление конфигов"
    rm -rf /etc/wireguard
    rm -f /etc/dnsmasq.d/wg-simple.conf
    rm -f /etc/sysctl.d/99-wg-simple.conf
    rm -f /etc/sysctl.d/99-wg-hardening.conf
    rm -f /etc/unbound/unbound.conf.d/wg-simple.conf
    rm -f /etc/stubby/stubby.yml
    # E5: удаляем dnsproxy юнит и бинарник
    rm -f /etc/systemd/system/dnsproxy.service
    rm -f /usr/local/bin/dnsproxy
    rm -f "${_AUDIT_LOG}" "${WG_ERR_LOG}"

    step "Восстановление AppArmor unbound"
    if command -v aa-enforce >/dev/null 2>&1; then
        aa-enforce /usr/sbin/unbound 2>/dev/null || true
    fi
    rm -f /etc/apparmor.d/disable/usr.sbin.unbound 2>/dev/null || true

    step "Восстановление DNS"
    # Исправление B3 (restore): восстанавливаем оригинальный симлинк-таргет если сохранён,
    # иначе подставляем backup-файл или дефолтный nameserver.
    # chattr -i оставляем на случай старых установок где ставился immutable-флаг.
    if ! _is_container && command -v chattr >/dev/null 2>&1; then
        chattr -i /etc/resolv.conf 2>/dev/null || true
    fi
    if [ -f /etc/resolv.conf.wg-bak-target ]; then
        local _orig_target
        _orig_target=$(cat /etc/resolv.conf.wg-bak-target 2>/dev/null || true)
        [ -n "${_orig_target}" ] && ln -sf "${_orig_target}" /etc/resolv.conf \
            && rm -f /etc/resolv.conf.wg-bak-target \
            || true
    elif [ -f /etc/resolv.conf.wg-bak ]; then
        cp -f /etc/resolv.conf.wg-bak /etc/resolv.conf
    else
        printf "nameserver 8.8.8.8\nnameserver 1.1.1.1\n" > /etc/resolv.conf
    fi
    systemctl unmask systemd-resolved 2>/dev/null || true
    rm -f /etc/systemd/resolved.conf.d/99-wireguard.conf
    rmdir /etc/systemd/resolved.conf.d 2>/dev/null || true

    echo ""
    echo -e "  ${GREEN}${BOLD}✔ Удаление завершено.${NC}"
    echo ""
    exit 0
}

# ════════════════════════════════════════════════════════════════
# ПЕРВОНАЧАЛЬНАЯ УСТАНОВКА
# ════════════════════════════════════════════════════════════════
firstInstall() {
    echo ""
    echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}  ║   🛡️   WireGuard Simple Server — Первоначальная установка    ║${NC}"
    echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    section "1/3 — Настройка сервера"
    echo ""
    echo -e "  ${DIM}Доступные сетевые интерфейсы:${NC}"
    ip -brief addr show | awk '{
        iface = $1; state = $2
        ipv4 = "—"
        for (i=3; i<=NF; i++) {
            if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\//) { ipv4 = $i; break }
        }
        printf "    - %-12s  %-8s  %s\n", iface, state, ipv4
    }'
    echo ""

    ask "Основной сетевой интерфейс (выход в интернет)" "" "MAIN_INTERFACE" ""
    validateInterface "${MAIN_INTERFACE}"
    validateIfaceName "${MAIN_INTERFACE}"

    ask "WG интерфейс" "" "SERVER_WG_NIC" "wg0"
    validateIfaceName "${SERVER_WG_NIC}"

    ask "Порт WireGuard" "" "SERVER_PORT" "51820"
    [[ "${SERVER_PORT}" =~ ^[0-9]{1,5}$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ] \
        || error "Недопустимый порт: '${SERVER_PORT}'"

    ask "MTU сервера" "" "SERVER_MTU" "1420"
    [[ "${SERVER_MTU}" =~ ^[0-9]+$ ]] && [ "${SERVER_MTU}" -ge 576 ] && [ "${SERVER_MTU}" -le 9000 ] \
        || { warn "Недопустимый MTU — используем 1420"; SERVER_MTU="1420"; }

    echo ""
    echo -ne "  ${CYAN}→ Определение публичного IP...${NC} "
    SERVER_PUB_IP=$(ip -4 addr show "${MAIN_INTERFACE}" | awk '/inet /{split($2,a,"/"); print a[1]; exit}')
    if [ -z "${SERVER_PUB_IP}" ]; then
        echo ""; warn "IPv4 не найден на ${MAIN_INTERFACE}"
        ask "Введи публичный IPv4 сервера" "" "SERVER_PUB_IP" ""
    elif [[ "${SERVER_PUB_IP}" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.) ]]; then
        echo ""
        warn "Обнаружен приватный IP: ${SERVER_PUB_IP} (за NAT)"
        hint "Если это VPS — введи реальный публичный IP. Для домашнего сервера — твой внешний IP."
        ask "Публичный IP сервера" "" "SERVER_PUB_IP" "${SERVER_PUB_IP}"
    else
        echo -e "${GREEN}${SERVER_PUB_IP}${NC}"
        read -rp "  Верно? Enter для подтверждения (или введи другой): " alt_ip
        [ -n "${alt_ip}" ] && SERVER_PUB_IP="${alt_ip}"
    fi
    info "Публичный IP: ${GREEN}${BOLD}${SERVER_PUB_IP}${NC}"
    # Финальная валидация — должен быть IPv4 или hostname
    if ! [[ "${SERVER_PUB_IP}" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] && \
       ! [[ "${SERVER_PUB_IP}" =~ ^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,253}[a-zA-Z0-9])?$ ]]; then
        error "Недопустимый публичный IP/хост: '${SERVER_PUB_IP}'"
    fi
    [ -z "${SERVER_PUB_IP}" ] && error "Публичный IP не задан — клиенты не смогут подключиться"
    # Предупреждение если hostname не резолвится
    if ! [[ "${SERVER_PUB_IP}" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        if ! getent hosts "${SERVER_PUB_IP}" >/dev/null 2>&1; then
            warn "Хостнейм '${SERVER_PUB_IP}' не резолвится — клиенты не смогут подключиться!"
            local _cnt; askYesNo "Продолжить несмотря на это?" "_cnt" "n"
            [ "${_cnt}" != "yes" ] && { warn "Отменено — укажи корректный IP или домен"; firstInstall; return; }
        fi
    fi

    echo ""
    while true; do
        ask "Подсеть IPv4 клиентов" "" "CLIENT_IPV4_SUBNET" "10.200.200.0/24"
        # Исправление #11: строгая валидация через python3 (отклоняет 999.x.x.x/99)
        if python3 -c "
import ipaddress, sys
try:
    net = ipaddress.IPv4Network(sys.argv[1], strict=False)
    # Запрещаем /31 и /32 — слишком малы для WireGuard-подсети
    if net.prefixlen > 30:
        sys.exit(1)
except ValueError:
    sys.exit(1)
" "${CLIENT_IPV4_SUBNET}" 2>/dev/null; then
            break
        fi
        warn "Неверный формат или недопустимый CIDR! Пример: 10.200.200.0/24 (поддерживаются /16../30)"
    done

    # Вопрос про IPv6
    echo ""
    askYesNo "Включить поддержку IPv6 для клиентов?" "ENABLE_IPV6" "y"
    if [ "${ENABLE_IPV6}" = "yes" ]; then
        while true; do
            ask "Подсеть IPv6 клиентов" "" "CLIENT_IPV6_SUBNET" "fd66:66:66::/64"
            # Исправление #11: строгая валидация IPv6 CIDR через python3
            if python3 -c "
import ipaddress, sys
try:
    net = ipaddress.IPv6Network(sys.argv[1], strict=False)
    if net.prefixlen > 126:
        sys.exit(1)
except ValueError:
    sys.exit(1)
" "${CLIENT_IPV6_SUBNET}" 2>/dev/null; then
                break
            fi
            warn "Неверный формат или недопустимый IPv6 CIDR! Пример: fd66:66:66::/64"
        done
    else
        CLIENT_IPV6_SUBNET=""
        info "IPv6 отключён — клиенты будут работать только по IPv4"
    fi

    # Вычисляем адрес сервера в WG-сети (.1)
    local ipv4_base="${CLIENT_IPV4_SUBNET%/*}"
    local ipv4_prefix="${CLIENT_IPV4_SUBNET##*/}"
    SERVER_IPV4_ADDR="${ipv4_base%.*}.1/${ipv4_prefix}"
    if [ "${ENABLE_IPV6}" = "yes" ] && [ -n "${CLIENT_IPV6_SUBNET}" ]; then
        local ipv6_base="${CLIENT_IPV6_SUBNET%/*}"
        local ipv6_prefix="${CLIENT_IPV6_SUBNET##*/}"
        SERVER_IPV6_ADDR="${ipv6_base%::*}::1/${ipv6_prefix}"
    else
        SERVER_IPV6_ADDR=""
    fi

    # Проверяем конфликт WG-подсети с локальными интерфейсами
    local _wg_net_base="${CLIENT_IPV4_SUBNET%/*}"
    local _wg_o1 _wg_o2 _wg_o3 _wg_o4 _wg_net_int _wg_mask _wg_net_min _wg_net_max
    IFS=. read -r _wg_o1 _wg_o2 _wg_o3 _wg_o4 <<< "${_wg_net_base}"
    # Исправление B1 (второй сайт): та же защита от восьмеричной интерпретации
    _wg_o1=$((10#${_wg_o1})); _wg_o2=$((10#${_wg_o2}))
    _wg_o3=$((10#${_wg_o3})); _wg_o4=$((10#${_wg_o4}))
    _wg_net_int=$(( (_wg_o1 << 24) | (_wg_o2 << 16) | (_wg_o3 << 8) | _wg_o4 ))
    _wg_mask=$(( 0xFFFFFFFF << (32 - ipv4_prefix) & 0xFFFFFFFF ))
    _wg_net_min=$(( _wg_net_int & _wg_mask ))
    _wg_net_max=$(( _wg_net_min | (~_wg_mask & 0xFFFFFFFF) ))
    local _conflict_found=0
    while IFS= read -r _iface_cidr; do
        [ -z "${_iface_cidr}" ] && continue
        local _ia _ip _pfx _ia1 _ia2 _ia3 _ia4 _ia_int _ia_mask _ia_min _ia_max
        _ip="${_iface_cidr%/*}"; _pfx="${_iface_cidr##*/}"
        IFS=. read -r _ia1 _ia2 _ia3 _ia4 <<< "${_ip}"
        # Исправление B1 (третий сайт): защита от восьмеричной интерпретации
        _ia1=$((10#${_ia1})); _ia2=$((10#${_ia2}))
        _ia3=$((10#${_ia3})); _ia4=$((10#${_ia4}))
        _ia_int=$(( (_ia1 << 24) | (_ia2 << 16) | (_ia3 << 8) | _ia4 ))
        _ia_mask=$(( 0xFFFFFFFF << (32 - _pfx) & 0xFFFFFFFF ))
        _ia_min=$(( _ia_int & _ia_mask ))
        _ia_max=$(( _ia_min | (~_ia_mask & 0xFFFFFFFF) ))
        # Пересечение: диапазоны перекрываются если один начинается до конца другого
        if [ "${_wg_net_min}" -le "${_ia_max}" ] && [ "${_ia_min}" -le "${_wg_net_max}" ]; then
            warn "Конфликт подсетей: WG ${CLIENT_IPV4_SUBNET} пересекается с локальным ${_iface_cidr}"
            _conflict_found=1
        fi
    done < <(ip -4 addr show 2>/dev/null | awk '/inet /{split($2,a,"/"); print a[1] "/" a[2]}')
    if [ "${_conflict_found}" -eq 1 ]; then
        warn "Конфликт маршрутизации возможен — рекомендуется выбрать другую подсеть"
        local _cnt; askYesNo "Продолжить несмотря на конфликт?" "_cnt" "n"
        [ "${_cnt}" != "yes" ] && { warn "Отменено — выбери другую подсеть"; firstInstall; return; }
    fi

    section "2/3 — Безопасность: белый список IP"
    echo ""
    echo -e "  ${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "  ${YELLOW}║   🛡️  ЧТО ТАКОЕ БЕЛЫЙ СПИСОК IP?                             ║${NC}"
    echo -e "  ${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}Политика фаервола: INPUT=DROP${NC}"
    echo -e "  ${DIM}Это значит: все входящие подключения к серверу заблокированы${NC}"
    echo -e "  ${DIM}по умолчанию. Никто не сможет достучаться до SSH, панели и т.п.${NC}"
    echo ""
    echo -e "  ${BOLD}Белый список${NC} — это список IP-адресов (твой домашний, офисный,${NC}"
    echo -e "  ${DIM}IP VPS-панели), которым разрешён ПОЛНЫЙ входящий доступ к серверу.${NC}"
    echo -e "  ${DIM}Только эти адреса смогут подключиться по SSH для управления.${NC}"
    echo ""
    echo -e "  ${BOLD}WG-порт (${SERVER_PORT}/UDP)${NC} ${DIM}открыт для всех — это нужно чтобы${NC}"
    echo -e "  ${DIM}клиенты VPN могли подключаться из любой точки мира.${NC}"
    echo ""
    echo -e "  ${DIM}Пример: твой домашний IP 203.0.113.5 → добавь его → SSH работает.${NC}"
    echo -e "  ${DIM}Если IP динамический — добавь CIDR подсети провайдера (203.0.113.0/24)${NC}"
    echo -e "  ${DIM}или используй VPN/выделенный IP для управления.${NC}"
    echo ""

    # Показываем текущий внешний IP
    local _my_ip
    _my_ip=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null \
          || wget -qO- --timeout=5 https://api.ipify.org 2>/dev/null \
          || echo "")
    if [ -n "${_my_ip}" ]; then
        echo -e "  ${YELLOW}Твой текущий IP: ${BOLD}${_my_ip}${NC}"
        echo ""
        local _add_self
        askYesNo "Добавить твой IP (${_my_ip}) в белый список?" "_add_self" "y"
        [ "${_add_self}" = "yes" ] && ALLOWED_IPS+=("${_my_ip}") && info "Добавлен: ${_my_ip}"
        echo ""
    fi

    # Цикл добавления IP
    local _idx=$(( ${#ALLOWED_IPS[@]} + 1 ))
    while true; do
        local _ip_input=""
        echo -ne "  ${CYAN}→ IP #${_idx} для белого списка${NC} ${DIM}(IPv4/CIDR, пусто = закончить)${NC}: "
        _WG_INTERACTIVE=1; read -r _ip_input; _WG_INTERACTIVE=0
        [ -z "${_ip_input}" ] && break
        # Исправление A4: строгая валидация через python3 ipaddress.
        # Старый regex принимал 999.999.999.999 и другой мусор.
        if python3 -c "
import ipaddress, sys
try:
    ipaddress.ip_network(sys.argv[1], strict=False)
except ValueError as e:
    print('Ошибка:', e, file=__import__('sys').stderr)
    sys.exit(1)
" "${_ip_input}" 2>/dev/null; then
            if [[ "${_ip_input}" =~ : ]]; then
                ALLOWED_IPS6+=("${_ip_input}")
            else
                ALLOWED_IPS+=("${_ip_input}")
            fi
            info "Добавлен: ${_ip_input}"
            _idx=$(( _idx + 1 ))
        else
            warn "Неверный IP/CIDR: '${_ip_input}' — проверь формат (например: 203.0.113.5 или 203.0.113.0/24)"
        fi
    done

    if [ "${#ALLOWED_IPS[@]}" -eq 0 ] && [ "${#ALLOWED_IPS6[@]}" -eq 0 ] 2>/dev/null; then
        echo ""
        echo -e "${RED}${BOLD}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}${BOLD}  ║   🚨  КРИТИЧЕСКОЕ ПРЕДУПРЕЖДЕНИЕ — БЕЛЫЙ СПИСОК ПУСТ        ║${NC}"
        echo -e "${RED}${BOLD}  ╠══════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${RED}${BOLD}  ║                                                              ║${NC}"
        echo -e "${RED}${BOLD}  ║  Политика INPUT=DROP заблокирует ВСЕ входящие соединения.   ║${NC}"
        echo -e "${RED}${BOLD}  ║  SSH-доступ к серверу будет ПОЛНОСТЬЮ ЗАКРЫТ.               ║${NC}"
        echo -e "${RED}${BOLD}  ║  Ты потеряешь управление сервером после установки!          ║${NC}"
        echo -e "${RED}${BOLD}  ║                                                              ║${NC}"
        echo -e "${RED}${BOLD}  ║  Открыт будет ТОЛЬКО WG-порт (${SERVER_PORT}/UDP).               ║${NC}"
        echo -e "${RED}${BOLD}  ║                                                              ║${NC}"
        echo -e "${RED}${BOLD}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${YELLOW}Для продолжения введи слово${NC} ${RED}${BOLD}ПОНИМАЮ${NC} ${YELLOW}(заглавными):${NC}"
        echo ""
        local _force_confirm=""
        read -rp "  Ввод: " _force_confirm
        if [ "${_force_confirm}" != "ПОНИМАЮ" ]; then
            warn "Отменено — вернись и добавь свой IP в белый список"
            firstInstall
            return
        fi
        echo ""
        warn "Продолжаем без белого списка. SSH будет недоступен — убедись что есть другой способ войти на сервер (консоль VPS, KVM, etc)."
        echo ""
    fi

    section "3/3 — Подтверждение"
    echo ""
    echo -e "  ${BOLD}Публичный IP:${NC}      ${GREEN}${SERVER_PUB_IP}${NC}"
    echo -e "  ${BOLD}Основной iface:${NC}    ${CYAN}${MAIN_INTERFACE}${NC}"
    echo -e "  ${BOLD}WG интерфейс:${NC}      ${CYAN}${SERVER_WG_NIC}${NC} порт ${YELLOW}${SERVER_PORT}${NC}"
    echo -e "  ${BOLD}Адрес сервера:${NC}     ${CYAN}${SERVER_IPV4_ADDR}${NC}"
    echo -e "  ${BOLD}Подсеть клиентов:${NC}  ${CYAN}${CLIENT_IPV4_SUBNET}${NC}"
    if [ "${ENABLE_IPV6:-yes}" = "yes" ] && [ -n "${SERVER_IPV6_ADDR:-}" ]; then
        echo -e "  ${BOLD}IPv6 сервера:${NC}      ${CYAN}${SERVER_IPV6_ADDR}${NC}"
        echo -e "  ${BOLD}IPv6 подсеть:${NC}      ${CYAN}${CLIENT_IPV6_SUBNET}${NC}"
    else
        echo -e "  ${BOLD}IPv6:${NC}              ${DIM}отключён${NC}"
    fi
    echo -e "  ${BOLD}MTU:${NC}               ${SERVER_MTU}"
    echo ""
    echo -e "  ${RED}${BOLD}Политика INPUT: DROP${NC}  — все входящие блокированы кроме:"
    echo -e "  ${YELLOW}WG UDP/${SERVER_PORT}${NC} — открыт (flood-лимит 200pps/IP)"
    if [ "${#ALLOWED_IPS[@]}" -gt 0 ]; then
        echo -e "  ${GREEN}Белый список:${NC}"
        local _ip
        for _ip in "${ALLOWED_IPS[@]+"${ALLOWED_IPS[@]}"}"; do
            echo -e "    ${GREEN}✔${NC}  ${_ip}"
        done
        for _ip in "${ALLOWED_IPS6[@]+"${ALLOWED_IPS6[@]}"}"; do
            [ -n "${_ip}" ] && echo -e "    ${GREEN}✔${NC}  ${_ip} (IPv6)"
        done
    else
        echo -e "  ${RED}Белый список: пуст${NC}"
    fi
    echo ""
    read -rp "  Всё верно? Enter для установки (Ctrl+C — отмена): "

    section "3/3 — Установка"
    saveConfig
    enableForwarding
    _applyKernelHardening
    createNft
    createServerConfig

    # ── DNS: всегда зашифрованный (DoT через stubby) ─────────────
    # Plain-режим удалён — DNS-трафик клиентов должен быть защищён.
    # Сначала поднимаем базовый dnsmasq (нужен для bind на WG-IP),
    # затем сразу переключаем на DoT.
    setupDnsmasq

    # Drop-in override для wg-quick (чтобы не падал при повторном up)
    mkdir -p "/etc/systemd/system/wg-quick@${SERVER_WG_NIC}.service.d"
    printf '[Service]\nExecStartPre=-/usr/bin/wg-quick down %%i\n' \
        > "/etc/systemd/system/wg-quick@${SERVER_WG_NIC}.service.d/override.conf"
    systemctl daemon-reload

    # Автозапуск
    systemctl enable nftables 2>/dev/null || true
    systemctl enable "wg-quick@${SERVER_WG_NIC}" 2>/dev/null || true
    systemctl enable dnsmasq 2>/dev/null || true

    # Поднимаем интерфейс
    wg-quick down "${SERVER_WG_NIC}" 2>/dev/null || true
    sleep 1
    wg-quick up "${SERVER_WG_NIC}" 2>/dev/null && info "WireGuard поднят!" || \
        warn "WireGuard не поднялся — проверь: wg-quick up ${SERVER_WG_NIC}"
    # Перезапускаем dnsmasq после поднятия WG-интерфейса —
    # только теперь он может bind на ${SERVER_IPV4_ADDR%%/*}
    systemctl restart dnsmasq 2>/dev/null && info "dnsmasq перезапущен" || \
        warn "dnsmasq не стартовал — journalctl -u dnsmasq -n 20"

    # ── Переключаем DNS на зашифрованный режим (обязательно) ─────
    # E8: предлагаем выбор DoT или DoH.
    # WG_DNS_BACKEND=dot|doh позволяет автоматизировать (по умолч. dot)
    echo ""
    echo -e "  ${CYAN}▶${NC} ${BOLD}Настройка зашифрованного DNS${NC}"
    echo -e "  ${DIM}Plain-режим недоступен. Выбери протокол шифрования:${NC}"
    echo ""
    echo -e "  ${YELLOW}1${NC})  🔐  ${WHITE}DoT${NC}  — DNS-over-TLS (stubby, порт 853)    ${DIM}[по умолчанию]${NC}"
    echo -e "  ${YELLOW}2${NC})  🌐  ${WHITE}DoH${NC}  — DNS-over-HTTPS (dnsproxy, порт 443) ${DIM}[обходит блокировки DNS]${NC}"
    echo ""
    local _dns_backend_choice
    if [ -n "${WG_DNS_BACKEND:-}" ]; then
        case "${WG_DNS_BACKEND}" in
            doh) _dns_backend_choice="2" ;;
            *)   _dns_backend_choice="1" ;;
        esac
        hint "WG_DNS_BACKEND=${WG_DNS_BACKEND} → выбор ${_dns_backend_choice}"
    else
        read -rp "  Выбор [1]: " _dns_backend_choice
    fi
    case "${_dns_backend_choice}" in
        2)
            _dns_setup_doh || {
                warn "DoH не настроен — пробуем DoT как fallback"
                _dns_setup_dot || warn "DoT тоже не настроен — DNS в plain-режиме (небезопасно!)"
            }
            ;;
        *)
            _dns_setup_dot || {
                warn "DoT не настроен — DNS остался в plain-режиме (небезопасно!)"
                warn "Исправь вручную: меню → 7 → 2 (DoT) или 3 (DoH)"
            }
            ;;
    esac

    # Logrotate
    cat > /etc/logrotate.d/wg-simple << 'LOGROTATE'
/var/log/wg-simple-audit.log
/var/log/wg-simple-trap.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}
LOGROTATE

    echo ""
    echo -e "${GREEN}${BOLD}  ╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}  ║   ✔  Установка завершена!                                    ║${NC}"
    echo -e "${GREEN}${BOLD}  ╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    info "Сервер: ${GREEN}${SERVER_PUB_IP}:${SERVER_PORT}${NC}"
    info "WG интерфейс: ${CYAN}${SERVER_WG_NIC}${NC} (${SERVER_IPV4_ADDR})"
    info "DNS для клиентов: ${CYAN}${SERVER_IPV4_ADDR%%/*}${NC} (dnsmasq → stubby → DoT 🔐)"
    echo ""
    echo -e "  ${DIM}Следующий шаг: меню → 1 → 1  (добавить первого клиента)${NC}"
    echo ""
    wg show 2>/dev/null || true
}

# ════════════════════════════════════════════════════════════════
# ПОДМЕНЮ КЛИЕНТОВ
# ════════════════════════════════════════════════════════════════
menuClients() {
    while true; do
        clear
        echo ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   👤  КЛИЕНТЫ — устройства подключённые к серверу            ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${DIM}Каждый клиент — одно устройство (телефон, ноутбук, ПК).${NC}"
        echo -e "  ${DIM}После добавления получишь QR-код для приложения WireGuard.${NC}"
        echo ""
        echo -e "  ${YELLOW}1${NC})  ➕  ${WHITE}Добавить клиента${NC}"
        echo -e "      ${DIM}Создаёт конфиг и QR-код. Нужно только ввести имя (iphone, laptop).${NC}"
        echo ""
        echo -e "  ${YELLOW}2${NC})  📋  ${WHITE}Список клиентов${NC}"
        echo -e "      ${DIM}Все устройства, их IP и последнее время онлайн.${NC}"
        echo ""
        echo -e "  ${YELLOW}3${NC})  📱  ${WHITE}Показать QR-код${NC}"
        echo -e "      ${DIM}Повторный вывод QR для существующего клиента.${NC}"
        echo ""
        echo -e "  ${YELLOW}4${NC})  ❌  ${WHITE}Отозвать клиента${NC}"
        echo -e "      ${DIM}Удаляет устройство — оно больше не сможет подключиться.${NC}"
        echo ""
        echo -e "  ${YELLOW}5${NC})  📁  ${WHITE}Папка с конфигами${NC}  ${DIM}(/etc/wireguard/clients/)${NC}"
        echo ""
        echo -e "  ${RED}0${NC})  ←   Назад"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1) addClient ;;
            2) listClients ;;
            3) showClientQR ;;
            4) revokeClient ;;
            5) step "Папка клиентов"; ls -la /etc/wireguard/clients/ 2>/dev/null || warn "Папка не найдена" ;;
            0) break ;;
            *) warn "Неверный выбор" ;;
        esac
        _pause
    done
}

# ════════════════════════════════════════════════════════════════
# ГЛАВНОЕ МЕНЮ
# ════════════════════════════════════════════════════════════════
# ════════════════════════════════════════════════════════════════
# ПАРАМЕТРЫ СЕРВЕРА — смена порта / MTU / публичного IP на лету
# ════════════════════════════════════════════════════════════════
_validPort() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
_validMtu()  { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 576 ] && [ "$1" -le 9000 ]; }
_validIp()   { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || [[ "$1" =~ ^([0-9a-fA-F:]+)$ ]] || [[ "$1" =~ ^[A-Za-z0-9.-]+$ ]]; }

_applyServerChanges() {
    # Перегенерируем серверный конфиг и nftables, поднимаем WG
    step "Применяю изменения"
    createNft           || { warn "nftables: ошибка"; return 1; }
    createServerConfig  || { warn "WG conf: ошибка"; return 1; }
    wg-quick down "${SERVER_WG_NIC}" 2>/dev/null || true
    sleep 1
    # Исправление #14: nftables не перезапускаем отдельно — PostUp уже загружает /etc/nftables.conf.
    # Двойная загрузка безвредна, но избыточна.
    wg-quick up "${SERVER_WG_NIC}" 2>/dev/null && info "WG поднят" || warn "WG не поднялся"
    systemctl restart dnsmasq  2>/dev/null || true
    return 0
}

_updateClientsEndpointPort() {
    # Обновляет Endpoint = host:PORT во всех клиентских .conf и перегенерирует QR
    local _cdir="/etc/wireguard/clients" _f _name
    [ -d "${_cdir}" ] || return 0
    shopt -s nullglob
    for _f in "${_cdir}"/*.conf; do
        sed -i -E "s|^(Endpoint[[:space:]]*=[[:space:]]*).*$|\1${SERVER_PUB_IP}:${SERVER_PORT}|" "${_f}"
        _name=$(basename "${_f}" .conf)
        qrencode -o "${_cdir}/${_name}.png" -t PNG < "${_f}" 2>/dev/null || true
    done
    shopt -u nullglob
}

# ════════════════════════════════════════════════════════════════
# МЕНЮ БЕЗОПАСНОСТИ — управление белым списком IP
# ════════════════════════════════════════════════════════════════
menuSecurity() {
    loadConfig
    while true; do
        clear
        echo ""
        echo -e "${RED}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}  ║   🔒  БЕЗОПАСНОСТЬ — белый список IP                         ║${NC}"
        echo -e "${RED}  ║      INPUT=DROP · только разрешённые IP имеют доступ         ║${NC}"
        echo -e "${RED}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${BOLD}Текущая политика:${NC}"
        echo -e "    ${RED}INPUT:${NC}   DROP  — все входящие блокированы"
        echo -e "    ${GREEN}OUTPUT:${NC}  ACCEPT — все исходящие разрешены"
        echo -e "    ${RED}FORWARD:${NC} DROP  — только WG-трафик"
        echo ""
        echo -e "  ${BOLD}WG UDP/${SERVER_PORT:-?}${NC} — открыт для всех (flood-лимит 200pps/IP)"
        echo ""

        # Показываем текущий белый список
        if [ "${#ALLOWED_IPS[@]}" -eq 0 ] && [ "${#ALLOWED_IPS6[@]}" -eq 0 ] 2>/dev/null; then
            echo -e "  ${RED}${BOLD}Белый список ПУСТ — SSH недоступен извне!${NC}"
        else
            echo -e "  ${GREEN}${BOLD}Белый список (полный входящий доступ):${NC}"
            local _ip
            for _ip in "${ALLOWED_IPS[@]+"${ALLOWED_IPS[@]}"}"; do
                echo -e "    ${GREEN}✔${NC}  ${_ip}"
            done
            for _ip in "${ALLOWED_IPS6[@]+"${ALLOWED_IPS6[@]}"}"; do
                [ -n "${_ip}" ] && echo -e "    ${GREEN}✔${NC}  ${_ip}  ${DIM}(IPv6)${NC}"
            done
        fi
        echo ""
        echo -e "  ${YELLOW}1${NC})  ➕  Добавить IP в белый список"
        echo -e "      ${DIM}Разрешить входящий доступ с нового адреса (SSH, управление).${NC}"
        echo ""
        echo -e "  ${YELLOW}2${NC})  ✏️   Редактировать IP в белом списке"
        echo -e "      ${DIM}Изменить существующий адрес — например если сменился IP.${NC}"
        echo ""
        echo -e "  ${YELLOW}3${NC})  ❌  Удалить IP из белого списка"
        echo -e "      ${DIM}Убрать адрес — он больше не будет иметь входящий доступ.${NC}"
        echo ""
        echo -e "  ${YELLOW}4${NC})  🔄  Переприменить правила (nftables + sysctl)"
        echo -e "      ${DIM}Если что-то пошло не так — пересоздать все правила фаервола.${NC}"
        echo ""
        echo -e "  ${YELLOW}5${NC})  🛡️   Переприменить kernel hardening"
        echo -e "      ${DIM}Повторно применить защитные параметры ядра (sysctl).${NC}"
        echo ""
        echo -e "  ${YELLOW}6${NC})  👁️   Показать текущие правила nftables"
        echo -e "      ${DIM}Полный дамп активных правил фаервола для диагностики.${NC}"
        echo -e "  ${RED}0${NC})  ←   Назад"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1)
                echo ""
                echo -e "  ${BOLD}Добавление IP-адресов в белый список${NC}"
                echo -e "  ${DIM}Можно вводить несколько адресов по одному.${NC}"
                echo -e "  ${DIM}Пустая строка — завершить и применить правила.${NC}"
                echo ""
                echo -e "  ${DIM}Примеры допустимых значений:${NC}"
                echo -e "  ${DIM}  203.0.113.5        — одиночный IPv4${NC}"
                echo -e "  ${DIM}  203.0.113.0/24     — пул: вся подсеть /24 (254 адреса)${NC}"
                echo -e "  ${DIM}  10.0.0.0/8         — крупный пул (для внутренней сети датацентра)${NC}"
                echo -e "  ${DIM}  2001:db8::1        — одиночный IPv6${NC}"
                echo -e "  ${DIM}  2001:db8::/32      — пул IPv6${NC}"
                echo ""
                echo -e "  ${YELLOW}⚠  Не добавляй 0.0.0.0/0 — это откроет все порты для всего мира!${NC}"
                echo ""
                local _added_count=0
                local _added_list=()
                while true; do
                    local _num=$(( ${#ALLOWED_IPS[@]} + ${#ALLOWED_IPS6[@]} + 1 ))
                    echo -ne "  ${CYAN}→ IP/CIDR #${_num}${NC} ${DIM}(пусто = готово)${NC}: "
                    _WG_INTERACTIVE=1; read -r _new_ip; _WG_INTERACTIVE=0
                    [ -z "${_new_ip}" ] && break
                    # Предупреждение о приватных адресах
                    if python3 -c "
import ipaddress, sys
try:
    net = ipaddress.ip_network(sys.argv[1], strict=False)
    if net.is_private:
        sys.exit(2)
except ValueError:
    sys.exit(1)
" "${_new_ip}" 2>/dev/null; then
                        : # публичный — всё ок
                    elif [ $? -eq 2 ]; then
                        echo -e "  ${YELLOW}⚠  ${_new_ip} — приватный адрес (192.168.x.x / 10.x.x.x / 172.16-31.x.x).${NC}"
                        echo -e "  ${DIM}Такие адреса имеют смысл только если у сервера есть приватный${NC}"
                        echo -e "  ${DIM}сетевой интерфейс (internal network у Hetzner, DO, Vultr и т.п.).${NC}"
                        echo -e "  ${DIM}Для обычного VPS эта запись никогда не сработает.${NC}"
                        local _force_priv
                        askYesNo "  Всё равно добавить ${_new_ip}?" "_force_priv" "n"
                        [ "${_force_priv}" != "yes" ] && { warn "Пропущено"; continue; }
                    else
                        warn "Неверный IP/CIDR: '${_new_ip}' — проверь формат"
                        continue
                    fi
                    # Проверка на дубликат
                    local _dup=0
                    local _chk
                    for _chk in "${ALLOWED_IPS[@]+"${ALLOWED_IPS[@]}"}" "${ALLOWED_IPS6[@]+"${ALLOWED_IPS6[@]}"}"; do
                        [ "${_chk}" = "${_new_ip}" ] && _dup=1 && break
                    done
                    if [ "${_dup}" -eq 1 ]; then
                        warn "${_new_ip} уже есть в белом списке — пропущено"
                        continue
                    fi
                    if [[ "${_new_ip}" =~ : ]]; then
                        ALLOWED_IPS6+=("${_new_ip}")
                    else
                        ALLOWED_IPS+=("${_new_ip}")
                    fi
                    _added_list+=("${_new_ip}")
                    _added_count=$(( _added_count + 1 ))
                    info "Добавлен: ${_new_ip}"
                done
                if [ "${_added_count}" -gt 0 ]; then
                    saveConfig
                    createNft
                    audit_log "security addAllowedIP count=${_added_count} list=${_added_list[*]}"
                    info "Добавлено адресов: ${_added_count} — правила применены"
                else
                    info "Ничего не добавлено"
                fi
                _pause ;;
            2)
                echo ""
                if [ "${#ALLOWED_IPS[@]}" -eq 0 ] && [ "${#ALLOWED_IPS6[@]}" -eq 0 ]; then
                    warn "Белый список пуст — нечего редактировать"
                    _pause; continue
                fi
                echo -e "  ${BOLD}Текущий белый список:${NC}"
                echo ""
                local _idx=1
                for _ip in "${ALLOWED_IPS[@]+"${ALLOWED_IPS[@]}"}"; do
                    echo -e "  ${YELLOW}${_idx}${NC}) ${_ip}"
                    _idx=$(( _idx + 1 ))
                done
                local _ipv4_count=$(( _idx - 1 ))
                for _ip in "${ALLOWED_IPS6[@]+"${ALLOWED_IPS6[@]}"}"; do
                    [ -n "${_ip}" ] && { echo -e "  ${YELLOW}${_idx}${NC}) ${_ip} ${DIM}(IPv6)${NC}"; _idx=$(( _idx + 1 )); }
                done
                echo ""
                read -rp "  Номер для редактирования: " _edit
                [[ "${_edit}" =~ ^[0-9]+$ ]] || { warn "Неверный ввод"; _pause; continue; }
                [ "${_edit}" -lt 1 ] || [ "${_edit}" -ge "${_idx}" ] && { warn "Номер вне диапазона"; _pause; continue; }
                if [ "${_edit}" -le "${_ipv4_count}" ]; then
                    local _old_val="${ALLOWED_IPS[$(( _edit - 1 ))]}"
                    echo ""
                    echo -e "  ${DIM}Текущее значение: ${WHITE}${_old_val}${NC}"
                    echo -e "  ${DIM}Введи новый IP/CIDR (пусто = отмена):${NC}"
                    echo -ne "  ${CYAN}→ Новый IP или CIDR:${NC} "
                    _WG_INTERACTIVE=1; read -r _new_val; _WG_INTERACTIVE=0
                    [ -z "${_new_val}" ] && { info "Отменено"; _pause; continue; }
                    if ! python3 -c "
import ipaddress, sys
try:
    ipaddress.ip_network(sys.argv[1], strict=False)
except ValueError:
    sys.exit(1)
" "${_new_val}" 2>/dev/null; then
                        warn "Неверный IP/CIDR: '${_new_val}'"
                        _pause; continue
                    fi
                    ALLOWED_IPS[$(( _edit - 1 ))]="${_new_val}"
                    saveConfig
                    createNft
                    audit_log "security editAllowedIP ${_old_val} -> ${_new_val}"
                    info "Изменено: ${_old_val} → ${_new_val} — правила применены"
                else
                    local _edit6=$(( _edit - _ipv4_count ))
                    local _i6=1 _old_val6=""
                    for _ip in "${ALLOWED_IPS6[@]+"${ALLOWED_IPS6[@]}"}"; do
                        [ -n "${_ip}" ] || continue
                        if [ "${_i6}" -eq "${_edit6}" ]; then _old_val6="${_ip}"; break; fi
                        _i6=$(( _i6 + 1 ))
                    done
                    echo ""
                    echo -e "  ${DIM}Текущее значение: ${WHITE}${_old_val6}${NC}"
                    echo -ne "  ${CYAN}→ Новый IPv6 или CIDR:${NC} "
                    _WG_INTERACTIVE=1; read -r _new_val6; _WG_INTERACTIVE=0
                    [ -z "${_new_val6}" ] && { info "Отменено"; _pause; continue; }
                    if ! python3 -c "
import ipaddress, sys
try:
    ipaddress.ip_network(sys.argv[1], strict=False)
except ValueError:
    sys.exit(1)
" "${_new_val6}" 2>/dev/null; then
                        warn "Неверный IPv6/CIDR: '${_new_val6}'"
                        _pause; continue
                    fi
                    local _new_arr6=() _i=1
                    for _ip in "${ALLOWED_IPS6[@]+"${ALLOWED_IPS6[@]}"}"; do
                        [ -n "${_ip}" ] || continue
                        if [ "${_i}" -eq "${_edit6}" ]; then
                            _new_arr6+=("${_new_val6}")
                        else
                            _new_arr6+=("${_ip}")
                        fi
                        _i=$(( _i + 1 ))
                    done
                    if [ "${#_new_arr6[@]}" -gt 0 ]; then
                        ALLOWED_IPS6=("${_new_arr6[@]}")
                    else
                        ALLOWED_IPS6=()
                    fi
                    saveConfig
                    createNft
                    audit_log "security editAllowedIP6 ${_old_val6} -> ${_new_val6}"
                    info "Изменено: ${_old_val6} → ${_new_val6} — правила применены"
                fi
                _pause ;;
            3)
                echo ""
                # Исправление A7: проверяем оба массива
                if [ "${#ALLOWED_IPS[@]}" -eq 0 ] && [ "${#ALLOWED_IPS6[@]}" -eq 0 ]; then
                    warn "Белый список пуст"
                    _pause; continue
                fi
                local _idx=1
                for _ip in "${ALLOWED_IPS[@]+"${ALLOWED_IPS[@]}"}"; do
                    echo -e "  ${YELLOW}${_idx}${NC}) ${_ip}"
                    _idx=$(( _idx + 1 ))
                done
                local _ipv4_count=$(( _idx - 1 ))
                for _ip in "${ALLOWED_IPS6[@]+"${ALLOWED_IPS6[@]}"}"; do
                    [ -n "${_ip}" ] && { echo -e "  ${YELLOW}${_idx}${NC}) ${_ip} ${DIM}(IPv6)${NC}"; _idx=$(( _idx + 1 )); }
                done
                echo ""
                read -rp "  Номер для удаления: " _del
                [[ "${_del}" =~ ^[0-9]+$ ]] || { warn "Неверный ввод"; _pause; continue; }
                [ "${_del}" -lt 1 ] || [ "${_del}" -ge "${_idx}" ] && { warn "Номер вне диапазона"; _pause; continue; }
                if [ "${_del}" -le "${_ipv4_count}" ]; then
                    local _new_arr=() _i=1
                    for _ip in "${ALLOWED_IPS[@]+"${ALLOWED_IPS[@]}"}"; do
                        [ "${_i}" -ne "${_del}" ] && _new_arr+=("${_ip}")
                        _i=$(( _i + 1 ))
                    done
                    if [ "${#_new_arr[@]}" -gt 0 ]; then
                        ALLOWED_IPS=("${_new_arr[@]}")
                    else
                        ALLOWED_IPS=()
                    fi
                else
                    local _del6=$(( _del - _ipv4_count ))
                    local _new_arr6=() _i=1
                    for _ip in "${ALLOWED_IPS6[@]+"${ALLOWED_IPS6[@]}"}"; do
                        [ -n "${_ip}" ] || continue
                        [ "${_i}" -ne "${_del6}" ] && _new_arr6+=("${_ip}")
                        _i=$(( _i + 1 ))
                    done
                    if [ "${#_new_arr6[@]}" -gt 0 ]; then
                        ALLOWED_IPS6=("${_new_arr6[@]}")
                    else
                        ALLOWED_IPS6=()
                    fi
                fi
                saveConfig
                createNft
                audit_log "security removeAllowedIP idx=${_del}"
                info "Удалено — правила применены"
                _pause ;;
            4)
                _autoBackup "before-security-reapply" || true
                createNft
                info "Правила переприменены"
                _pause ;;
            5)
                _applyKernelHardening
                _pause ;;
            6)
                echo ""
                nft list ruleset 2>/dev/null || warn "nftables не запущен"
                _pause ;;
            0) break ;;
            *) warn "Неверный выбор"; sleep 1 ;;
        esac
    done
}


menuServerSettings() {
    loadConfig
    while true; do
        clear
        echo ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   ⚙️   ПАРАМЕТРЫ СЕРВЕРА — смена на лету                     ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  Текущие значения:"
        echo -e "    ${DIM}WG порт:       ${NC}${WHITE}${SERVER_PORT:-?}${NC}"
        echo -e "    ${DIM}MTU:           ${NC}${WHITE}${SERVER_MTU:-1420}${NC}"
        echo -e "    ${DIM}Публичный IP:  ${NC}${WHITE}${SERVER_PUB_IP:-?}${NC}"
        echo -e "    ${DIM}DNS режим:     ${NC}${WHITE}${DNS_MODE:-plain}${NC}   ${DIM}(меняется в пункте «DNS режим»)${NC}"
        echo ""
        echo -e "  ${YELLOW}1${NC})  🔢  Сменить ${WHITE}порт WG${NC}        ${DIM}(обновит nftables, сервер и все клиентские .conf + QR)${NC}"
        echo -e "  ${YELLOW}2${NC})  📏  Сменить ${WHITE}MTU${NC}            ${DIM}(перезапишет [Interface] MTU и перезапустит WG)${NC}"
        echo -e "  ${YELLOW}3${NC})  🌐  Сменить ${WHITE}публичный IP/домен${NC} ${DIM}(обновит Endpoint у всех клиентов + QR)${NC}"
        echo -e "  ${RED}0${NC})  ←   Назад"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1)
                echo ""
                read -rp "  Новый UDP-порт WG [${SERVER_PORT}]: " _new
                [ -z "${_new}" ] && { info "Без изменений"; _pause; continue; }
                _validPort "${_new}" || { warn "Неверный порт (1–65535)"; _pause; continue; }
                if ss -lun 2>/dev/null | awk '{print $5}' | grep -qE ":${_new}\$"; then
                    warn "Порт ${_new} уже занят другим UDP-сервисом"; _pause; continue
                fi
                local _confirm
                askYesNo "Сменить порт ${SERVER_PORT} → ${_new} ?" "_confirm" "y"
                [ "${_confirm}" != "yes" ] && { info "Отменено"; _pause; continue; }
                _autoBackup "before-port-change" || true
                local _old="${SERVER_PORT}"
                SERVER_PORT="${_new}"
                saveConfig
                if _applyServerChanges; then
                    _updateClientsEndpointPort
                    audit_log "changePort ${_old} -> ${_new}"
                    info "Порт изменён: ${_old} → ${_new}"
                    hint "Раздай клиентам новые .conf/QR из /etc/wireguard/clients/"
                else
                    warn "Ошибка применения — откатываю порт"
                    SERVER_PORT="${_old}"; saveConfig; _applyServerChanges || true
                fi
                _pause ;;
            2)
                echo ""
                read -rp "  Новое значение MTU [${SERVER_MTU:-1420}] (576–9000): " _new
                [ -z "${_new}" ] && { info "Без изменений"; _pause; continue; }
                _validMtu "${_new}" || { warn "Неверный MTU"; _pause; continue; }
                _autoBackup "before-mtu-change" || true
                local _old="${SERVER_MTU:-1420}"
                SERVER_MTU="${_new}"
                saveConfig
                if _applyServerChanges; then
                    audit_log "changeMTU ${_old} -> ${_new}"
                    info "MTU изменён: ${_old} → ${_new}"
                else
                    warn "Ошибка — откатываю MTU"
                    SERVER_MTU="${_old}"; saveConfig; _applyServerChanges || true
                fi
                _pause ;;
            3)
                echo ""
                read -rp "  Новый публичный IP или домен [${SERVER_PUB_IP}]: " _new
                [ -z "${_new}" ] && { info "Без изменений"; _pause; continue; }
                _validIp "${_new}" || { warn "Неверный формат IP/домена"; _pause; continue; }
                local _confirm
                askYesNo "Сменить публичный адрес на ${_new} ?" "_confirm" "y"
                [ "${_confirm}" != "yes" ] && { info "Отменено"; _pause; continue; }
                _autoBackup "before-pubip-change" || true
                local _old="${SERVER_PUB_IP}"
                SERVER_PUB_IP="${_new}"
                saveConfig
                _updateClientsEndpointPort
                audit_log "changePubIP ${_old} -> ${_new}"
                info "Публичный адрес изменён: ${_old} → ${_new}"
                hint "Сервер перезапускать не нужно — раздай новые .conf/QR клиентам"
                _pause ;;
            0) break ;;
            *) warn "Неверный выбор"; sleep 1 ;;
        esac
    done
}
menu() {
    loadConfig
    while true; do
        clear
        echo ""
        echo -e "${YELLOW}  ╔═════════════════════════════════════════════════════════════╗${NC}"
        printf "${YELLOW}  ║      🛡️   WireGuard Simple Server  —  v%-20s  ║${NC}\n" "${VERSION}"
        echo -e "${YELLOW}  ║                  Один сервер · Прямое подключение            ║${NC}"
        echo -e "${YELLOW}  ╚═════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        _statusBar
        echo ""
        echo -e "${WHITE}  ┌─────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${WHITE}  │  ОСНОВНЫЕ                                                   │${NC}"
        echo -e "${WHITE}  └─────────────────────────────────────────────────────────────┘${NC}"
        echo ""
        echo -e "  ${YELLOW}1${NC})  👤  ${WHITE}Клиенты${NC}               ${DIM}— добавить, QR, список, отозвать${NC}"
        echo -e "  ${YELLOW}2${NC})  📊  ${WHITE}Статус WireGuard${NC}      ${DIM}— пиры, трафик, last handshake${NC}"
        echo -e "  ${YELLOW}3${NC})  📄  ${WHITE}Логи${NC}                  ${DIM}— WG, dnsmasq, nftables, аудит${NC}"
        echo ""
        echo -e "${WHITE}  ┌─────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${WHITE}  │  СИСТЕМА                                                    │${NC}"
        echo -e "${WHITE}  └─────────────────────────────────────────────────────────────┘${NC}"
        echo ""
        echo -e "  ${YELLOW}4${NC})  🚀  ${WHITE}Автозапуск${NC}            ${DIM}— включить/выключить, перезапустить${NC}"
        echo -e "  ${YELLOW}5${NC})  💾  ${WHITE}Бэкап / Восстановление${NC} ${DIM}— сохранить и восстановить конфиги${NC}"
        echo -e "  ${YELLOW}6${NC})  🔄  ${WHITE}Перезапустить всё${NC}"
        echo -e "  ${YELLOW}7${NC})  🔒  ${WHITE}DNS режим${NC}             ${DIM}— plain / Unbound / DoT (stubby)${NC}"
        echo -e "  ${YELLOW}8${NC})  ⚙️   ${WHITE}Параметры сервера${NC}     ${DIM}— сменить порт / MTU / публичный IP${NC}"
        echo -e "  ${YELLOW}9${NC})  🛡️   ${WHITE}Безопасность${NC}          ${DIM}— белый список IP · INPUT=DROP · hardening${NC}"
        echo -e "  ${RED}10${NC}) 💣  ${RED}Удалить всё${NC}           ${DIM}— НЕОБРАТИМО${NC}"
        echo ""
        echo -e "  ${RED}0${NC})  🚪  Выход"
        echo ""
        echo -ne "  ${YELLOW}${BOLD}Введи номер и нажми Enter:${NC} "
        read -r opt
        case "${opt}" in
            1) menuClients ;;
            2) menuWGStatus; _pause ;;
            3) menuLogs ;;
            4) menuAutostart ;;
            5) menuBackup ;;
            6) _autoBackup "restart" || true
               step "Перезапуск"
               # nftables НЕ перезапускаем отдельно: wg-quick down выполнит PostDown
               # (удаляет таблицы), wg-quick up — PostUp (пересоздаёт из файла)
               wg-quick down "${SERVER_WG_NIC}" 2>/dev/null || true
               sleep 1
               wg-quick up "${SERVER_WG_NIC}" && info "WG поднят" || warn "WG не поднялся"
               case "${DNS_MODE:-plain}" in
                   unbound) systemctl restart unbound 2>/dev/null || true ;;
                   dot)     systemctl restart stubby  2>/dev/null || true ;;
               esac
               systemctl restart dnsmasq 2>/dev/null || true
               _pause ;;
            7) menuDns ;;
            8) menuServerSettings ;;
            9) menuSecurity ;;
            10) _autoBackup "before-remove" || true
               removeAll ;;
            0) echo ""; exit 0 ;;
            *) warn "Введи цифру от 0 до 10"; sleep 1 ;;
        esac
    done
}

# ════════════════════════════════════════════════════════════════
# ТОЧКА ВХОДА
# ════════════════════════════════════════════════════════════════
isRoot
checkBashVersion
[[ "${1:-}" == "--remove" ]] && { removeAll; exit 0; }
if [ ! -f "${CONFIG_FILE}" ]; then
    installPackages
    firstInstall
fi
menu
