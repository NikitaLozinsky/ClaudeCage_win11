# ClaudeCage: Windows 11 Hardened Sandbox for Claude Desktop & CLI

Непробиваемая изолированная среда («клетка») для запуска **Claude Desktop (Electron)** и **Claude Code (CLI)** исключительно через туннель **AmneziaVPN** с аппаратным WFP Kill Switch на уровне ядра Windows и защитой от антифрод-телеметрии.

---

## Архитектура и принцип Fail-Closed
- **Kernel-level WFP Kill Switch:** Запрещает любым процессам `Claude Desktop`, `Claude Code CLI`, а также изолированным дочерним бинарникам `C:\ClaudeCage\bin\node.exe` и `curl.exe` отправку сетевых пакетов через физические/виртуальные адаптеры хоста (Ethernet, Wi-Fi, Hyper-V, Bluetooth). Трафик разрешён исключительно через интерфейс WireGuard (`AmneziaVPN`).
- **Total Lockdown при падении VPN:** Если AmneziaVPN выключен или упал, правила WFP переводятся в режим тотальной блокировки по всем интерфейсам. Ни один TCP SYN или UDP пакет не покинет систему.
- **Защита от DNS-утечек (Anti-Leak):**
  - Отключен механизм Smart Multi-Homed Name Resolution (SMHNR), предотвращая параллельную отправку DNS-запросов на провайдерские DNS.
  - Отключен мультикаст LLMNR.
  - Прямые запросы на порт 53 к DNS-серверам провайдера заблокированы в фаерволе.
- **Защита от IPv6-утечек:** Отключен протокол IPv6 (`ms_tcpip6`) на физическом адаптере, а для изолированных процессов заблокирован весь исходящий IPv6-трафик (`2000::/3`, `fc00::/7`, `fe80::/10`).
- **Антифрод-телеметрия (Electron & Node.js):**
  - Подмена таймзоны (`$env:TZ = $vpnTimezone`), исключающая расхождение между IP-геолокацией (NL) и системным временем (Europe/Moscow).
  - Подмена локали и языка (`$env:LANG = en_US.UTF-8`, `--lang=en-US`, `--accept-lang=en-US,en;q=0.9`).
  - Подавление утечек WebRTC в Chromium (`--force-webrtc-ip-handling-policy=disable_non_proxied_udp`, `--disable-webrtc`).

---

## Содержимое репозитория
```text
C:\ClaudeCage\
├── .git\                      # Полная Git-история версий (v0..v4)
├── backups\baseline\          # Дампы реестра (.reg), профиля и сетевых настроек до изменений
├── bin\                       # Изолированные копии node.exe и curl.exe
├── Sync-ClaudeFirewall.ps1    # Ядро WFP Kill Switch (расчет адаптеров и установка правил)
├── Start-ClaudeDesktop.ps1    # Обёртка запуска Claude Desktop с антифрод-флагами
├── Invoke-ClaudeCLI.ps1       # Обёртка запуска Claude Code CLI (подключена в $PROFILE)
├── Install-ClaudeProfileHook.ps1 # Установка функции `claude` в PowerShell $PROFILE
├── Test-CageLeaks.ps1         # Автотест на утечки IP, DNS, IPv6, Timezone и Kill Switch
├── Set-DnsHardening.ps1       # Применение политик DNS & IPv6 Hardening
└── Rollback-System.ps1        # Полный откат системы к v0-baseline в один клик
```

---

## Быстрый старт

### 1. Проверка состояния и утечек
```powershell
& "C:\ClaudeCage\Test-CageLeaks.ps1" -Detailed
```

### 2. Запуск Claude Desktop (GUI)
```powershell
& "C:\ClaudeCage\Start-ClaudeDesktop.ps1"
```

### 3. Запуск Claude Code (CLI)
Команда `claude` автоматически перенаправляется через изолированный раннер:
```powershell
claude --version
claude
```

### 4. Управление WFP Kill Switch
```powershell
# Просмотр статуса адаптеров и правил WFP
& "C:\ClaudeCage\Sync-ClaudeFirewall.ps1" -Status

# Принудительная пересинхронизация правил
& "C:\ClaudeCage\Sync-ClaudeFirewall.ps1" -Enforce

# Временное снятие правил группы ClaudeKillSwitch
& "C:\ClaudeCage\Sync-ClaudeFirewall.ps1" -Remove
```

### 5. Полный откат системы к Baseline (v0-baseline)
```powershell
& "C:\ClaudeCage\Rollback-System.ps1"
```
