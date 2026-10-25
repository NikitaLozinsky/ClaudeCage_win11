# ClaudeCage: Windows 11 Hardened Sandbox for Claude Desktop & CLI

Непробиваемая изолированная среда («клетка») для запуска **Claude Desktop (Electron)** и **Claude Code (CLI)** исключительно через туннель **AmneziaVPN** с аппаратным WFP Kill Switch на уровне ядра Windows и защитой от антифрод-телеметрии.

---

## Архитектура v6-audit-hardened

По итогам Red Team аудита безопасности внедрены следующие решения:

1. **Kernel-Level DNS Guard (NRPT — Name Resolution Policy Table):**
   - Через `Add-DnsClientNrptRule` все обращения к доменам `.anthropic.com`, `.claude.ai`, `.claude.com`, `.sentry.io`, `.stripe.com`, `.intercom.io` принудительно направляются системным DNS-клиентом (`svchost.exe -k NetworkService`) исключительно на внутренний DNS туннеля (`100.64.0.1`).
   - Если VPN падает, `svchost.exe` не перенаправляет запросы к DNS провайдера (`46.61.250.136`), а мгновенно завершает их ошибкой (Fail-Closed).
2. **24/7 Source IP (LocalAddress) Inversion — Устранение гонок состояний (TOCTOU):**
   - Исходящий трафик процессов Claude заблокирован со всех исходных IP-адресов, КРОМЕ подсети CGNAT Amnezia (`100.64.0.0/10`) и Loopback (`127.0.0.0/8`).
   - При падении VPN локальный сокет переходит на `192.168.0.68` и **мгновенно (0 мс) блокируется на уровне ядра WFP** без необходимости перезапуска скриптов фаервола.
3. **Make-Before-Break (Атомарное обновление правил):**
   - Фаервол никогда не удаляет старые правила до того, как новые сгенерированы и применены. Окно уязвимости равно нулю.
4. **Защита дочерних процессов и сетевых утилит:**
   - В правила фаервола автоматически включены `git.exe`, `git-remote-https.exe`, `git-remote-http.exe`, `ssh.exe` и любые MCP-серверы из `%APPDATA%\Claude\claude_desktop_config.json`.
   - В рантайм Node.js внедрена опция `$env:NODE_OPTIONS = "--dns-result-order=ipv4first"`.
5. **Защита от утечек геолокации и трея:**
   - Перед стартом `Start-ClaudeDesktop.ps1` принудительно завершаются зависшие в трее процессы Claude, гарантируя применение новых `$env:TZ` и флагов Chromium.
   - Запрещен доступ к Windows Location API (`NonPackaged` -> `Deny`).
   - Использованы валидные Chromium-флаги (`--force-webrtc-ip-handling-policy=disable_non_proxied_udp`, `--enforce-webrtc-ip-permission-check`, `--disable-features=AsyncDns,DnsOverHttpsUpgrade,WebRtcHideLocalIpsWithMdns`).

---

## Структура репозитория
```text
C:\ClaudeCage\
├── .git\                         # Полная Git-история версий (v0..v6)
├── backups\baseline\             # Дампы реестра (.reg), профиля и сетевых настроек до изменений
├── bin\                          # Изолированные копии node.exe и curl.exe
├── logs\                         # Логи и метрики трафика (cage_traffic.log, cage_metrics.json)
├── Sync-ClaudeFirewall.ps1       # WFP Kill Switch: 24/7 LocalAddress Inversion + Make-Before-Break
├── Start-ClaudeDesktop.ps1       # Обёртка запуска Claude Desktop (очистка трея, флаги Chromium)
├── Invoke-ClaudeCLI.ps1          # Обёртка запуска Claude Code CLI (подключена в $PROFILE)
├── Watch-ClaudeCage.ps1          # Скрипт-логгер сокетов реального времени
├── Test-CageLeaks.ps1            # Тестовый комплекс на 9 проверок безопасности
├── Set-DnsHardening.ps1          # Настройка NRPT, SMHNR и Location Guard
├── Install-ClaudeProfileHook.ps1 # Интеграция функции `claude` в PowerShell $PROFILE
└── Rollback-System.ps1           # Полный откат системы к v0-baseline в один клик
```

---

## Команды управления

```powershell
# 1. Аудит безопасности и утечек (9 тестов)
& "C:\ClaudeCage\Test-CageLeaks.ps1" -Detailed

# 2. Запуск Claude Desktop
& "C:\ClaudeCage\Start-ClaudeDesktop.ps1"

# 3. Запуск Claude CLI
claude

# 4. Мониторинг сокетов реального времени
& "C:\ClaudeCage\Watch-ClaudeCage.ps1"

# 5. Полный откат к v0-baseline
& "C:\ClaudeCage\Rollback-System.ps1"
```
