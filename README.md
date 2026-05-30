<div align="center">

# 🛡️ WireGuard Simple Server

**Простой и безопасный WireGuard-сервер с максимальной защитой**

[![Version](https://img.shields.io/badge/версия-2.0--patched--v13-blue?style=for-the-badge&logo=github)](https://github.com/avar-soft/wg-simple-server)
[![Bash](https://img.shields.io/badge/Bash-4.3+-green?style=for-the-badge&logo=gnu-bash)](https://www.gnu.org/software/bash/)
[![License](https://img.shields.io/badge/лицензия-MIT-orange?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/платформа-Ubuntu-purple?style=for-the-badge&logo=linux)](https://ubuntu.com)

*Один скрипт — полноценный VPN-сервер. Клиенты подключаются напрямую, без сложных туннелей.*  
*nftables · sysctl hardening · UDP flood-лимит · DoT · DoH · IPv6.*

</div>

---

## 🤔 Зачем это нужно?

В отличие от сложных решений с GeoIP и балансировщиками — этот скрипт решает одну задачу и решает её хорошо: **поднять надёжный WireGuard-сервер за 2 минуты** с максимальной защитой из коробки.

- 🔒 **INPUT=DROP** — все входящие соединения заблокированы по умолчанию, открыт только WG-порт
- 🛡️ **Белый список IP** — SSH и управление доступны только с твоих адресов
- 🔐 **Зашифрованный DNS** — DoT через stubby или DoH через dnsproxy, plain-режим удалён
- 👥 **Прямое подключение клиентов** — телефон, ноутбук, ПК подключаются напрямую к серверу
- 📱 **QR-коды** — добавление клиента занимает 30 секунд

---

## ✨ Возможности

### 🔥 Файрвол — максимальная защита

Политика **INPUT=DROP, FORWARD=DROP, OUTPUT=ACCEPT** через nftables. Разрешено только явно:

| Правило | Описание |
|---------|----------|
| **WG UDP-порт** | Открыт для всех + flood-лимит 200 pkt/s per IP |
| **Белый список** | IPv4/IPv6 адреса с полным входящим доступом (SSH) |
| **ESTABLISHED/RELATED** | Ответы на исходящие соединения |
| **ICMP PMTU** | destination-unreachable, packet-too-big — только для PMTU Discovery |
| **DNS от клиентов** | WG-интерфейс → dnsmasq :53 |

Дополнительно:
- **TCP аномальные флаги** — NULL/XMAS/SYN+FIN/SYN+RST/FIN scan дропаются в `prerouting_raw`
- **UDP flood-лимит** — per-IP счётчик в динамическом nftables-наборе с таймаутом 10s
- **MSS Clamping** — предотвращает залипание HTTPS при нестандартном MTU WireGuard

---

### 🔐 DNS — только зашифрованный

Plain-режим (открытый UDP/53) удалён. Три варианта на выбор:

#### Unbound — рекурсивный резолвер
Сервер сам резолвит от корневых серверов. Не доверяет никаким апстримам.
```
Клиент → dnsmasq → Unbound (127.0.0.1:5335) → root servers
```

#### DoT — DNS-over-TLS через stubby
Запросы шифруются по TLS 1.3, провайдер не видит DNS.
```
Клиент → dnsmasq → stubby (127.0.0.1:8053) → DoT (порт 853) → апстрим
```

#### DoH — DNS-over-HTTPS через dnsproxy
Работает через стандартный HTTPS порт 443 — обходит блокировки DNS.
```
Клиент → dnsmasq → dnsproxy (127.0.0.1:5053) → HTTPS (порт 443) → апстрим
```

**Провайдеры DoT** (21 вариант):

| Провайдер | Адреса | Особенность |
|-----------|--------|-------------|
| ☁️ **Cloudflare** | 1.1.1.1 / 1.0.0.1 | Быстрый, no-log |
| ☁️ **Cloudflare Family** | 1.1.1.3 / 1.0.0.3 | Блокирует малварь + adult |
| 🛡️ **Quad9** | 9.9.9.9 / 149.112.112.112 | Блокирует малварь, DNSSEC |
| 🔍 **Google** | 8.8.8.8 / 8.8.4.4 | Классика |
| 🚫 **AdGuard DNS** | 94.140.14.14 / 94.140.15.15 | Блокирует рекламу |
| 🔒 **Mullvad** | 194.242.2.2 / 194.242.2.3 | No-log, Швеция |
| 🌐 **DNS0.eu** | 193.110.81.0 / 185.253.5.0 | Европа, privacy |
| … и ещё 14 | OpenDNS, AdGuard Family, deSEC, CIRA, NextDNS… | |
| 🔀 **ВСЕ сразу** | Round-robin по 20 провайдерам | Максимальная отказоустойчивость |

**Провайдеры DoH** (9 вариантов): Cloudflare, Cloudflare Family, Google, Quad9, AdGuard, AdGuard Family, Mullvad, NextDNS, ВСЕ сразу.

---

### 👥 Клиенты

- **Автовыдача IP** — следующий свободный адрес из подсети, без конфликтов
- **IPv4 + IPv6** — dual-stack из коробки
- **QR-код** — в терминале и PNG-файл для мессенджеров
- **Full-tunnel / Split-tunnel / Свой CIDR** — выбор режима при добавлении
- **PSK** — preshared key для дополнительного слоя шифрования
- **Отзыв** — удаляет пира из живого WG без перезапуска

---

### 🔒 Kernel Hardening

При установке применяется максимальный набор sysctl:

- `rp_filter=2` (LOOSE) — обязателен для WireGuard, strict ломает туннель
- TCP SYN Cookies, SYN backlog 4096 — защита от SYN-flood
- Отключены ICMP-редиректы — вектор MITM
- ASLR=2, kptr_restrict=2, dmesg_restrict=1 — hardening ядра
- Лог «мартианских» пакетов

Все параметры сохраняются в `/etc/sysctl.d/99-wg-hardening.conf`.

---

### 💾 Бэкап и восстановление

Бэкап сохраняет:
- `/etc/wireguard/` — все конфиги и ключи
- `/etc/nftables.conf` — правила файрвола
- `/etc/systemd/system/` — systemd-юниты и override'ы
- `/etc/sysctl.d/` — параметры ядра

Хранятся последние **10 архивов**, старые удаляются автоматически. Автобэкап создаётся перед каждой опасной операцией.

---

### 📊 Мониторинг и логи

- **Статус пиров** — last handshake, трафик rx/tx в МБ
- **Тест резолвинга** — dig/nslookup прямо из меню
- **Аудит** — все действия пишутся в `/var/log/wg-simple-audit.log`
- **ERR-trap** — все ненулевые коды возврата в `/var/log/wg-simple-trap.log`
- **Логи сервисов** — WG, dnsmasq, nftables, stubby/dnsproxy из одного меню

---

### ⚙️ Параметры сервера на лету

Без пересоздания конфига с нуля — прямо из меню:

- **Смена порта** — обновляет nftables, серверный конфиг и все клиентские `.conf` + QR
- **Смена MTU** — перезаписывает `[Interface] MTU` и перезапускает WG
- **Смена публичного IP/домена** — обновляет `Endpoint` у всех клиентов + QR

---

## 📋 Требования

| Параметр | Значение |
|----------|----------|
| **ОС** | Ubuntu 22.04+ / Debian 11+ |
| **Права** | root |
| **Bash** | ≥ 4.3 |
| **Архитектура** | amd64, arm64, armv7 |
| **RAM** | ≥ 256 MB |
| **Диск** | ≥ 500 MB свободного места |
| **Сеть** | Публичный IP (VPS или выделенный сервер) |

**Зависимости устанавливаются автоматически:** `wireguard` · `nftables` · `curl` · `iproute2` · `qrencode` · `dnsmasq` · `python3` · `openssl` · `xxd`

Для DoT дополнительно: `stubby`  
Для DoH дополнительно: `dnsproxy` (скачивается автоматически с GitHub Releases)  
Для Unbound дополнительно: `unbound`

---

## ⚡ Быстрый старт

### Установка за 1 команду

```bash
curl -fsSL https://raw.githubusercontent.com/avar-soft/wg-simple-server/main/wg-simple-server.sh \
  -o wg-simple-server.sh \
  && chmod +x wg-simple-server.sh \
  && sudo bash wg-simple-server.sh
```

При первом запуске скрипт:

1. Устанавливает зависимости
2. Задаёт несколько вопросов (интерфейс, порт, подсеть, белый список IP)
3. Генерирует ключи WireGuard
4. Настраивает nftables + kernel hardening
5. Настраивает зашифрованный DNS (DoT или DoH на выбор)
6. Запускает все сервисы и открывает главное меню

**Весь процесс занимает ~2 минуты.**

### Последующие запуски

```bash
sudo bash wg-simple-server.sh
```

### Удаление

```bash
sudo bash wg-simple-server.sh --remove
```

---

## 📖 Использование

### Добавление клиента

```
Главное меню → 1) Клиенты → 1) Добавить клиента
```

Введи имя устройства (например `iphone` или `work-laptop`). Скрипт:
- Выдаёт следующий свободный IP из подсети
- Предлагает выбор Full-tunnel / Split-tunnel / Свой CIDR
- Показывает QR-код прямо в терминале
- Сохраняет `.conf` и `.png` в `/etc/wireguard/clients/`

QR-код сканируется приложением WireGuard (iOS / Android) — готово.

### Настройка DNS

```
Главное меню → 7) DNS режим
```

```
1)  🔁  Unbound   — рекурсивный резолвер, без апстрима
2)  🔐  DoT       — dnsmasq → stubby → провайдер по TLS (порт 853)
3)  🌐  DoH       — dnsmasq → dnsproxy → провайдер по HTTPS (порт 443)
4)  🔄  Перезапустить текущий DNS-стек
```

### Управление безопасностью

```
Главное меню → 9) Безопасность
```

- Добавить/редактировать/удалить IP из белого списка
- Переприменить правила nftables
- Просмотреть текущую политику файрвола

---

## 🔧 Интерактивное меню

```
  ╔═════════════════════════════════════════════════════════════╗
  ║      🛡️   WireGuard Simple Server  —  v2.0                  ║
  ║                  Один сервер · Прямое подключение           ║
  ╚═════════════════════════════════════════════════════════════╝

  WG: UP  NFT: ●  DNS: ● [DoT]  Клиентов: 3  203.0.113.1:51820

  ┌─────────────────────────────────────────────────────────────┐
  │  ОСНОВНЫЕ                                                   │
  └─────────────────────────────────────────────────────────────┘

  1)  👤  Клиенты               — добавить, QR, список, отозвать
  2)  📊  Статус WireGuard      — пиры, трафик, last handshake
  3)  📄  Логи                  — WG, dnsmasq, nftables, аудит

  ┌─────────────────────────────────────────────────────────────┐
  │  СИСТЕМА                                                    │
  └─────────────────────────────────────────────────────────────┘

  4)  🚀  Автозапуск            — включить/выключить, перезапустить
  5)  💾  Бэкап / Восстановление — сохранить и восстановить конфиги
  6)  🔄  Перезапустить всё
  7)  🔒  DNS режим             — Unbound / DoT / DoH
  8)  ⚙️   Параметры сервера     — сменить порт / MTU / публичный IP
  9)  🛡️   Безопасность          — белый список IP · INPUT=DROP
 10)  💣  Удалить всё           — НЕОБРАТИМО

  0)  🚪  Выход
```

---

## ⚙️ Автоматизация

Скрипт поддерживает переменные окружения для полностью неинтерактивного запуска (CI, cloud-init, Ansible):

```bash
# Выбор провайдера DoT (1..21, по умолч. 1 = Cloudflare)
export WG_DOT_PROVIDER=3     # Quad9

# Выбор провайдера DoH (1..9, по умолч. 1 = Cloudflare)
export WG_DOH_PROVIDER=7     # Mullvad

# Выбор DNS-бэкенда при установке: dot | doh (по умолч. dot)
export WG_DNS_BACKEND=doh

# Расширенное логирование ошибок в stderr
export WG_DEBUG=1
```

Пример полностью автоматической установки:

```bash
export WG_DNS_BACKEND=dot
export WG_DOT_PROVIDER=1
echo "1" | sudo bash wg-simple-server.sh
```

---

## 🔒 Безопасность

Скрипт разработан с акцентом на безопасность кода:

- **`set -uo pipefail`** — немедленная остановка при необъявленных переменных и ошибках в pipe
- **Валидация всех входных данных** — имена клиентов, порты, IP-адреса через `python3 ipaddress`
- **`_atomic_write()`** — конфиги перезаписываются через `mktemp` + `mv` (rename(2)), никаких частичных записей
- **Без `eval`** — `loadConfig` парсит файл конфига через `grep/while read`, без выполнения кода
- **ERR-trap** — все ненулевые коды возврата логируются с контекстом (функция, строка, команда)
- **Автобэкап** — создаётся перед каждой деструктивной операцией (смена порта, MTU, removeAll)
- **Аудит лог** — все действия пользователя пишутся с timestamp и именем пользователя
- **Контейнер-детект** — `chattr +i` пропускается внутри Docker/LXC/OpenVZ

---

## 📁 Структура файлов

```
/etc/wireguard/
├── wg0.conf                    # Серверный конфиг WireGuard
├── server_private.key          # Приватный ключ сервера (600)
├── .wg-simple.conf             # Конфигурация скрипта (600)
└── clients/
    ├── iphone.conf             # Конфиг клиента
    ├── iphone.png              # QR-код PNG
    └── laptop.conf

/etc/nftables.conf              # Правила файрвола (auto-generated)
/etc/dnsmasq.d/wg-simple.conf  # Конфиг DNS
/etc/stubby/stubby.yml          # Конфиг DoT (если активен)
/etc/systemd/system/
└── dnsproxy.service            # Юнит DoH (если активен)
/usr/local/bin/dnsproxy         # Бинарник DoH (если активен)

/etc/sysctl.d/
├── 99-wg-simple.conf           # IP forwarding
└── 99-wg-hardening.conf        # Kernel hardening

/var/backups/wg-simple/         # Автобэкапы (хранятся последние 10)
/var/log/wg-simple-audit.log    # Аудит действий
/var/log/wg-simple-trap.log     # Лог ошибок ERR-trap
/etc/logrotate.d/wg-simple      # Ротация логов (weekly, 4 недели)
```

---

## 📝 Журнал изменений

**v2.0-patched-v13 — текущая версия**

- 🌐 Добавлен DNS-over-HTTPS через dnsproxy (8 провайдеров + все сразу)
- 🐛 `menuDns` пункт «Перезапустить»: неверный fallback `:-dot` исправлен на `:-plain`
- 🐛 `_dns_stop_all`: dnsproxy не останавливался при смене режима — занимал порт 5053
- 🐛 `removeAll`: не удалял dnsproxy-юнит и бинарник
- 🐛 `menuAutostart`: нет ветки doh в enable/disable/restart/статус
- 🐛 `_statusBar` / `menuWGStatus`: режим doh отображался как plain⚠

**v2.0-patched-v12**

- ⚙️ `_dns_setup_dot`: поддержка `WG_DOT_PROVIDER` для неинтерактивного запуска

**v2.0-patched-v11**

- 🐛 `menuSecurity`: `ALLOWED_IPS=("${arr[@]}")` падало при пустом массиве в Bash 4.3

**v2.0-patched-v10**

- 🐛 `createNft`: исправлен порядок check→delete→load (был delete→check→load — оставлял сервер без firewall при ошибке)

**v2.0 (оригинал)**

- 🚀 Первый релиз: WireGuard, nftables, dnsmasq, DoT, kernel hardening, IPv4+IPv6

---

## 🤝 Участие в разработке

Pull requests приветствуются. Для значительных изменений — открой Issue для обсуждения.

**Правила:**

- Весь bash через `set -uo pipefail`
- Пользовательский ввод — только через валидацию `python3 ipaddress` или regex
- Временные файлы — через `_atomic_write()` или `mktemp` с очисткой
- Изменения DNS-стека — обязательно обновить все места: `_dns_stop_all`, `removeAll`, `menuAutostart`, `menuWGStatus`, `_statusBar`, `firstInstall`
- Комментарии к нетривиальным решениям обязательны

---

## 📄 Лицензия

MIT © [avar-soft](https://github.com/avar-soft)

---

<div align="center">

**Сделано с ❤️ для тех, кто ценит приватность и безопасность**

⭐ Если проект полезен — поставь звезду!

</div>

