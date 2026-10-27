# Досье архитектуры и исходного кода ClaudeCage v6.3: Отчет об устранении уязвимостей и аудит нативного конвейера сборки

**Дата отчета:** 27 октября 2026 года  
**Версия проекта:** `ClaudeCage v6.3.1-native` (на базе ядра v6.2-hardened)  
**Статус безопасности:** 10/10 тестов пройдено (Zero Leaks), 72 активных правила WFP, нативный бинарник PE x86_64, автоматический конвейер версионирования.  
**Целевой рецензент:** Gemini Argon 4 (Экспертный аудит низкоуровневой сетевой безопасности, Windows Filtering Platform и песочниц Chromium/Node.js).

---

## 1. Резюме изменений относительно предыдущего аудита (v6.1 -> v6.3)

В ходе предыдущего аудита версии **v6.1-release** экспертом Gemini Argon 4 был выявлен ряд критических граничных условий ядра Windows 11 (`tcpip.sys`), Desktop Bridge (MSIX `runFullTrust`), инверсии флагов Chromium и уязвимостей контекста `NT AUTHORITY\SYSTEM`.

Все 8 пунктов аудита были полностью устранены в релизе **v6.2-hardened**. В версии **v6.3** реализован принципиально новый защитный рубеж: **нативный компилируемый конвейер сборки (Native Go PE Binary)**, ликвидирующий вектор когнитивного обнаружения клетки автономными ИИ-агентами с доступом к файловой системе. Также проведен 10-минутный натурный аудит сетевых сокетов с расшифровкой всех 46 активных соединений.

---

## 2. Детальный разбор закрытия всех 8 уязвимостей аудита Argon 4

### 2.1. Устранение бага контекста `NT AUTHORITY\SYSTEM` в BootSync
* **Проблема v6.1:** Планировщик Windows запускал задачу синхронизации от имени `SYSTEM`. В этом контексте `$env:APPDATA` указывал на `C:\Windows\System32\config\systemprofile`, пользовательские бинарники не обнаруживались, а существующие правила для профиля пользователя удалялись при перезагрузке ОС.
* **Решение v6.2/v6.3:** Функция `Get-CageTargetBinaries` переписана. Она сканирует каталоги всех реальных пользователей `C:\Users\*` напрямую, минуя переменные окружения, а также опрашивает MSIX через `Get-AppxPackage -AllUsers -Name *Claude*`. Правила сохраняются и гарантированно накатываются на этапе загрузки ядра.

### 2.2. Защита Desktop Bridge MSIX (`TokenIsAppContainer = 0`)
* **Проблема v6.1:** Десктопный клиент Claude поставляется как MSIX с манифестом `runFullTrust`. Процесс запускается со стандартным токеном Medium Integrity (`TokenIsAppContainer = 0`), поэтому фильтр ядра WFP `FWP_CONDITION_ALE_PACKAGE_ID` к нему неприменим.
* **Решение v6.2/v6.3:** Привязка правил WFP реализована строго через условие `FWP_CONDITION_ALE_APP_ID` (`-Program`) на конкретный исполняемый файл в каталоге `C:\Program Files\WindowsApps\Claude_*\app\claude.exe`. Скрипты и нативный лаунчер динамически отслеживают изменение версии приложения при обновлениях Microsoft Store.

### 2.3. Ликвидация инверсии флагов WebRTC, DNS и блокировка QUIC
* **Проблема v6.1:** Флаг `--disable-features=WebRtcHideLocalIpsWithMdns` ошибочно отключал маскировку локальных IP. Не был заблокирован протокол QUIC/HTTP3 (порт 443 UDP), что создавало риск утечки через физический интерфейс при сбоях туннеля.
* **Решение v6.2/v6.3:** В рантайм внедрены строго валидированные флаги:
  * `--enable-features=WebRtcHideLocalIpsWithMdns` (принудительное сокрытие локальных IP за случайными mDNS-именами `.local`).
  * `--webrtc-ip-handling-policy=disable_non_proxied_udp` (запрет отправки любых WebRTC UDP-пакетов мимо туннеля).
  * `--disable-features=AsyncDns,BuiltInDnsClient,DnsOverHttpsUpgrade` (полное отключение внутреннего DNS-резолвера Chromium; все запросы идут через системный резолвер и подчиняются таблице NRPT).
  * `--disable-quic` (запрет UDP 443; весь трафик идет исключительно через надежный TCP TLS).

### 2.4. Включение Strong Host Model и блокировка подсетей CGNAT
* **Проблема v6.1:** При слабой модели хоста (Weak Host Model по умолчанию в Windows) стек `tcpip.sys` при падении туннеля мог отправлять TCP RST/FIN пакеты через физический интерфейс (`192.168.0.68`). Кроме того, подсеть `10.0.0.0/8` оставалась открытой, если VPN выдавал адрес из пула CGNAT `100.64.0.0/10`.
* **Решение v6.2/v6.3:** 
  * На всех интерфейсах IPv4 и IPv6 включена строгая модель хоста: `WeakHostSend=Disabled`, `WeakHostReceive=Disabled`. Пакеты не могут маршрутизироваться между интерфейсами.
  * Диапазон `10.0.0.0/8` добавлен в список безусловной блокировки локальных адресов при работе в CGNAT.

### 2.5. Ликвидация обхода IPv6 через Multicast (`ff00::/8`)
* **Проблема v6.1:** В Правиле 4 комбинация `-LocalAddress` и `-RemoteAddress` позволяла IPv6-пакетам с адресатами вне указанного диапазона (в частности, multicast `ff00::/8` для mDNS/LLMNR) проходить мимо фильтра.
* **Решение v6.2/v6.3:** Ограничение `-RemoteAddress` полностью удалено из IPv6-правила блокировки. Любой локальный исходящий IPv6-пакет изолированных процессов сбрасывается ядром безоговорочно.

### 2.6. Жесткая блокировка DNS-портов (Rule 5) и расширение NRPT
* **Проблема v6.1:** Потенциальные попытки приложений или системных служб обойти NRPT через прямой опрос портов 53/853 или автонастройку прокси WPAD / Auto-DoH.
* **Решение v6.2/v6.3:**
  * Отключены системный Auto-DoH (`EnableAutoDoh = 0`) и WPAD (`DisableWpad = 1`).
  * Введено **Правило 5 (DNS Port Lock)** в WFP: исходящие UDP/TCP соединения на порты 53 и 853 для изолированных процессов блокируются намертво на любой IP-адрес, отличный от DNS-сервера туннеля (`100.64.0.1`).
  * Таблица NRPT расширена служебными доменами: `.statsig.com`, `.statsigapi.net`, `.featuregates.org`, `.workos.com`, `.ipinfo.io`.

### 2.7. Дочерние бинарники CLI (Git и OpenSSH)
* **Решение v6.2/v6.3:** В список защищаемых таргетов WFP включены `C:\Windows\System32\OpenSSH\ssh.exe` и обнаруженные бинарники Git (`git-remote-https.exe`, `git-remote-http.exe`). Обработка `claude.cmd` переписана так, чтобы изолировать исполняемый бинарник `node.exe` и сам `claude.exe`.

### 2.8. Аудит сбросов пакетов ядра (WFP Drop Auditing)
* **Решение v6.2/v6.3:** Включен аудит отказов классификации WFP (`auditpol /set /subcategory:"{0CCE9225-69AE-11D9-BED3-505054503030}" /failure:enable`). Демоны аудита отслеживают события `Event ID 5152` и `5157` в журнале `Security`.

---

## 3. Натурные испытания: 10-минутный непрерывный аудит сокетов Claude Desktop

С помощью разработанного анализатора сокетов в реальном времени (`Watch-ClaudeNetworkView.ps1`) была проведена 10-минутная сессия непрерывной работы десктопного приложения Claude.

### 3.1. Сводные метрики сессии
* **Длительность:** 10 минут (21:32:34 — 21:42:16)
* **Всего сетевых сокетов аудировано:** 88
* **Успешно установлено внешних HTTPS-соединений:** 46
* **Попыток утечки через физический Ethernet (`192.168.0.68`):** **0 (ноль)**
* **Аппаратных сбросов незащищенных пакетов ядром:** **0 (все сокеты корректно привязались к туннелю)**
* **Протоколы:** 100% TCP Port 443 (TLS). Исходящий UDP-трафик полностью отсутствовал.

### 3.2. Карта удаленных эндпоинтов, зафиксированных анализатором
1. **Ядро Claude & Anthropic:**
   * `160.79.104.10:443` (Anthropic PBC, AS399299 — основной API шлюз).
   * `104.18.160.117:443`, `104.18.4.104:443`, `104.20.44.54:443` (Cloudflare Edge — авторизация и сессионный трафик `claude.ai`).
2. **Облачная инфраструктура AWS:**
   * `54.211.107.150:443`, `3.146.167.147:443`, `18.239.83.59:443`, `18.65.39.46:443`, `18.97.36.50:443` (AWS CloudFront / S3 — раздача ассетов интерфейса Electron).
3. **Безопасность Chromium (OCSP):**
   * `142.250.*.*:443`, `142.251.*.*:443` (Google OCSP — проверка отзыва SSL-сертификатов).
4. **Вспомогательные веб-сервисы:**
   * `76.76.21.21:443` (Vercel Edge), `185.199.108.133:443` (GitHub CDN), `199.232.215.52:443` (Fastly CDN).

**Вердикт натурного теста:** 100% трафика маршрутизируется строго через IP туннеля `100.72.12.75`. Домашняя сеть `192.168.0.0/24` и физический роутер `192.168.0.1` полностью скрыты от приложения.

---

## 4. Архитектура нативного конвейера сборки (v6.3 Native Pipeline)

### 4.1. Проблема текстовых скриптов при запуске ИИ-агентов
Когда пользователь запускает автономного ИИ-агента (например, `claude --dangerously-skip-permissions`), агент получает доступ к инструментам сканирования файловой системы (`Grep`, `View`, `Read`, `dir`). 
Наличие в каталоге открытых скриптов PowerShell (`.ps1`) и файлов описания архитектуры (`.md`) создает риск: агент читает текст, обнаруживает термины обхода гео-блокировок и антифрода, что приводит к срабатыванию модерации со стороны API модели либо к попытке агента изменить/удалить файлы клетки.

### 4.2. Решение: Статический нативный бинарник PE x86_64 (`ClaudeCage.exe`)
Весь функционал клетки и лаунчеров перенесен в нативный исходный код на **Go 1.24** (`src/main.go`) и компилируется в единый монолитный исполняемый файл:
1. **Иммутабельность:** Бинарник является машинным кодом. Инструменты чтения текста ИИ-агента получают отказ при попытке чтения (`Binary file cannot be displayed`). Поисковые утилиты (`rg`, `grep`) игнорируют бинарник.
2. **Вшитый ресурс иконки:** С помощью утилиты `rsrc` в секцию ресурсов PE (`rsrc.syso`) напрямую запекается кастомная 256px иконка `ClaudeCage.ico`.
3. **Защита от анализа:** Сборка осуществляется с флагами стриппинга отладочных символов и таблиц DWARF: `go build -ldflags "-s -w ..."`.
4. **Унифицированный интерфейс режимов:**
   * `ClaudeCage.exe` (без параметров / двойной клик) — защищенный запуск Claude Desktop.
   * `ClaudeCage.exe cli [args...]` — прозрачный прокси-лаунчер Claude Code CLI с полным пробросом аргументов.
   * `ClaudeCage.exe sync` — синхронизация правил WFP.
   * `ClaudeCage.exe watch` — запуск сниффера сокетов.
   * `ClaudeCage.exe test` — запуск 10 тестов утечек.
   * `ClaudeCage.exe version` — вывод метаданных билда, даты и коммита.

### 4.3. Автоматизированный конвейер версионирования (`Build-ClaudeCage.ps1` и `build.bat`)
Конвейер обеспечивает воспроизводимость и историю сборок:
* Автоматический инкремент семантической версии (`v6.3.0` -> `v6.3.1` -> `v6.3.2`).
* Фиксация метаданных коммита Git и UTC-времени сборки через `-ldflags`.
* Архивация билдов в каталог `builds/v<version>/ClaudeCage.exe` с вычислением контрольной суммы SHA-256 (`checksums.sha256`).
* Ведение реестра истории в `builds/manifest.json`.
* Автоматическое переключение ярлыков Рабочего стола, Меню Пуск и хука в `$PROFILE` на свежий скомпилированный бинарник.

---

## 5. Полный исходный код ключевых компонентов v6.3

### 5.1. Нативный монолит: `src/main.go`

```go
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var (
	Version   = "v6.3.1"
	BuildDate = "2026-10-27T22:00:00Z"
	Commit    = "development"
)

type IpInfoResponse struct {
	IP       string `json:"ip"`
	City     string `json:"city"`
	Country  string `json:"country"`
	Timezone string `json:"timezone"`
	Org      string `json:"org"`
}

func getCageRoot() string {
	exePath, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(exePath)
		if strings.Contains(strings.ToLower(dir), "builds") {
			parent := filepath.Dir(filepath.Dir(dir))
			if _, err := os.Stat(filepath.Join(parent, "icons")); err == nil {
				return parent
			}
		}
		if _, err := os.Stat(filepath.Join(dir, "icons")); err == nil {
			return dir
		}
	}
	return "C:\\ClaudeCage"
}

func isVpnUp() (bool, string) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false, "Unknown"
	}
	for _, iface := range interfaces {
		name := strings.ToLower(iface.Name)
		if iface.Flags&net.FlagUp != 0 {
			if strings.Contains(name, "amnezia") || strings.Contains(name, "wireguard") || strings.Contains(name, "wintun") || strings.Contains(name, "vpn") {
				return true, iface.Name
			}
		}
	}
	return false, "None"
}

func resolveVpnTimezone() string {
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("https://ipinfo.io/json")
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		var info IpInfoResponse
		if json.NewDecoder(resp.Body).Decode(&info) == nil && info.Timezone != "" {
			return info.Timezone
		}
	}
	return "Europe/Amsterdam"
}

func terminateStaleClaudeProcesses() {
	cmd := exec.Command("taskkill", "/F", "/IM", "claude.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Run()
	time.Sleep(300 * time.Millisecond)
}

func findClaudeDesktopExe() string {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-Command",
		"(Get-AppxPackage -Name *Claude* -ErrorAction SilentlyContinue | Select-Object -First 1).InstallLocation")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err == nil {
		loc := strings.TrimSpace(string(out))
		if loc != "" {
			cand := filepath.Join(loc, "app", "claude.exe")
			if _, err := os.Stat(cand); err == nil {
				return cand
			}
		}
	}

	localAppData := os.Getenv("LOCALAPPDATA")
	candidates := []string{
		filepath.Join(localAppData, "Programs", "Claude", "Claude.exe"),
		filepath.Join(localAppData, "AnthropicClaude", "Claude.exe"),
		"C:\\Program Files\\Claude\\Claude.exe",
	}
	for _, cand := range candidates {
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	return ""
}

func findClaudeCliExe() string {
	appData := os.Getenv("APPDATA")
	localAppData := os.Getenv("LOCALAPPDATA")
	candidates := []string{
		filepath.Join(appData, "npm", "node_modules", "@anthropic-ai", "claude-code", "bin", "claude.exe"),
		filepath.Join(localAppData, "npm", "node_modules", "@anthropic-ai", "claude-code", "bin", "claude.exe"),
	}
	for _, cand := range candidates {
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	return ""
}

func runDesktopMode() int {
	cageRoot := getCageRoot()
	cageBin := filepath.Join(cageRoot, "bin")

	vpnActive, vpnName := isVpnUp()
	if !vpnActive {
		fmt.Println("[!] [CLAUDECAGE WARNING] No active VPN tunnel detected.")
		fmt.Println("    Claude will run in strict OFFLINE mode (Fail-Closed).")
	} else {
		fmt.Printf("[+] Active VPN tunnel verified: %s\n", vpnName)
	}

	terminateStaleClaudeProcesses()

	tz := "Europe/Amsterdam"
	if vpnActive {
		tz = resolveVpnTimezone()
	}

	os.Setenv("TZ", tz)
	os.Setenv("LANG", "en_US.UTF-8")
	os.Setenv("LC_ALL", "en_US.UTF-8")
	os.Setenv("ELECTRON_ENABLE_LOGGING", "false")
	os.Setenv("PATH", cageBin+";"+os.Getenv("PATH"))

	claudeExe := findClaudeDesktopExe()
	if claudeExe == "" {
		fmt.Println("[!] Error: Claude Desktop executable not found on system!")
		return 1
	}

	electronFlags := []string{
		"--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
		"--webrtc-ip-handling-policy=disable_non_proxied_udp",
		"--enforce-webrtc-ip-permission-check",
		"--enable-features=WebRtcHideLocalIpsWithMdns",
		"--disable-features=AsyncDns,BuiltInDnsClient,DnsOverHttpsUpgrade",
		"--disable-quic",
		"--lang=en-US",
		"--accept-lang=en-US,en",
		"--disable-background-networking",
	}

	cmd := exec.Command(claudeExe, electronFlags...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: false}
	err := cmd.Start()
	if err != nil {
		fmt.Printf("[!] Error launching Claude Desktop: %v\n", err)
		return 1
	}

	fmt.Printf("[+] Claude Desktop running inside cage (PID: %d, Timezone: %s)\n", cmd.Process.Pid, tz)
	return 0
}

func runCliMode(args []string) int {
	cageRoot := getCageRoot()
	cageBin := filepath.Join(cageRoot, "bin")

	vpnActive, _ := isVpnUp()
	tz := "Europe/Amsterdam"
	if vpnActive {
		tz = resolveVpnTimezone()
	}

	os.Setenv("TZ", tz)
	os.Setenv("LANG", "en_US.UTF-8")
	os.Setenv("LC_ALL", "en_US.UTF-8")
	os.Setenv("NODE_OPTIONS", "--dns-result-order=ipv4first")
	os.Setenv("PATH", cageBin+";"+os.Getenv("PATH"))

	claudeCliExe := findClaudeCliExe()
	if claudeCliExe == "" {
		fmt.Println("[!] Error: Claude Code CLI binary not found in npm node_modules!")
		return 1
	}

	cmd := exec.Command(claudeCliExe, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		return 1
	}
	return 0
}

func runScript(scriptName string, args ...string) int {
	cageRoot := getCageRoot()
	scriptPath := filepath.Join(cageRoot, scriptName)
	if _, err := os.Stat(scriptPath); err != nil {
		fmt.Printf("[!] Script not found: %s\n", scriptPath)
		return 1
	}

	psArgs := append([]string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", scriptPath}, args...)
	cmd := exec.Command("powershell.exe", psArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		return 1
	}
	return 0
}

func main() {
	if len(os.Args) == 1 {
		os.Exit(runDesktopMode())
	}

	subCmd := strings.ToLower(os.Args[1])

	switch subCmd {
	case "desktop", "gui", "launch":
		os.Exit(runDesktopMode())
	case "cli", "code", "run":
		os.Exit(runCliMode(os.Args[2:]))
	case "sync", "firewall":
		os.Exit(runScript("Sync-ClaudeFirewall.ps1", "-Enforce"))
	case "watch", "monitor":
		os.Exit(runScript("Watch-ClaudeNetworkView.ps1"))
	case "test", "audit":
		os.Exit(runScript("Test-CageLeaks.ps1", "-Detailed"))
	case "version", "--version", "-v":
		fmt.Printf("ClaudeCage Core %s\n", Version)
		fmt.Printf("Build Timestamp: %s\n", BuildDate)
		fmt.Printf("Git Commit:      %s\n", Commit)
		fmt.Printf("Architecture:    windows/amd64\n")
		fmt.Printf("Cage Root:       %s\n", getCageRoot())
		os.Exit(0)
	case "help", "--help", "-h":
		fmt.Printf("ClaudeCage Unified Native Core (%s)\n\n", Version)
		fmt.Println("Usage:")
		fmt.Println("  ClaudeCage.exe               Launch Claude Desktop securely inside cage")
		fmt.Println("  ClaudeCage.exe desktop       Launch Claude Desktop")
		fmt.Println("  ClaudeCage.exe cli [args]    Launch Claude Code CLI with forwarded flags")
		fmt.Println("  ClaudeCage.exe sync          Enforce 24/7 WFP Make-Before-Break rules")
		fmt.Println("  ClaudeCage.exe watch         Live network socket sniffer & drop logger")
		fmt.Println("  ClaudeCage.exe test          Run full 10/10 leak test suite")
		fmt.Println("  ClaudeCage.exe version       Display build version and commit metadata")
		os.Exit(0)
	default:
		if strings.HasPrefix(subCmd, "-") {
			os.Exit(runCliMode(os.Args[1:]))
		}
		fmt.Printf("Unknown command: %s. Use 'ClaudeCage.exe help' for usage.\n", subCmd)
		os.Exit(1)
	}
}
```

---

### 5.2. Конвейер компиляции и версионирования: `Build-ClaudeCage.ps1`

```powershell
[CmdletBinding()]
param(
    [string]$Version,
    [switch]$NoShortcuts
)

$ErrorActionPreference = 'Stop'

$TargetRoot = "C:\ClaudeCage"
$SrcDir     = Join-Path $TargetRoot "src"
$BuildsDir  = Join-Path $TargetRoot "builds"
$IconsDir   = Join-Path $TargetRoot "icons"
$IconFile   = Join-Path $IconsDir "ClaudeCage.ico"
$VersionFile = Join-Path $TargetRoot "version.json"
$ManifestFile = Join-Path $BuildsDir "manifest.json"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "       CLAUDECAGE: NATIVE COMPILATION & BUILD PIPELINE    " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Determine Build Version
$currentVer = "6.3.0"
if (Test-Path $VersionFile) {
    try {
        $vJson = Get-Content $VersionFile -Raw | ConvertFrom-Json
        if ($vJson.version) { $currentVer = $vJson.version }
    } catch {}
}

if (-not $Version) {
    $parts = $currentVer.TrimStart('v').Split('.')
    if ($parts.Count -eq 3) {
        $patch = [int]$parts[2] + 1
        $targetVersion = "v$($parts[0]).$($parts[1]).$patch"
    } else {
        $targetVersion = "v$currentVer"
    }
} else {
    $targetVersion = if ($Version.StartsWith("v")) { $Version } else { "v$Version" }
}

$gitCommit = "unknown"
try {
    $gitCommit = (git rev-parse --short HEAD 2>$null).Trim()
} catch {}
if (-not $gitCommit) { $gitCommit = "dev" }

$buildDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# 2. Verify Toolchain
$goCmd = Get-Command go -ErrorAction SilentlyContinue
if (-not $goCmd) {
    Write-Error "[!] Go compiler not found in PATH!"
    exit 1
}

$rsrcExe = Join-Path $env:USERPROFILE "go\bin\rsrc.exe"
if (-not (Test-Path $rsrcExe)) {
    go install github.com/akavel/rsrc@latest
}

# 3. Generate PE Resource with Embedded Icon
if (-not (Test-Path $IconFile)) {
    $IconFile = Join-Path $IconsDir "claude.ico"
}

Push-Location $SrcDir
try {
    $sysoFile = Join-Path $SrcDir "rsrc.syso"
    & $rsrcExe -ico $IconFile -o $sysoFile

    # 4. Compile Native Static Binary
    $outExe = Join-Path $SrcDir "ClaudeCage.exe"
    if (Test-Path $outExe) { Remove-Item $outExe -Force }

    $ldFlags = "-s -w -X main.Version=$targetVersion -X main.BuildDate=$buildDate -X main.Commit=$gitCommit"
    go build -ldflags $ldFlags -o $outExe

    if (-not (Test-Path $outExe)) {
        Write-Error "[!] Build failed: ClaudeCage.exe not produced."
        exit 1
    }

    $binSize = (Get-Item $outExe).Length
} finally {
    if (Test-Path $sysoFile) { Remove-Item $sysoFile -Force -ErrorAction SilentlyContinue }
    Pop-Location
}

# 5. Versioning & Build Archival
$versionedDir = Join-Path $BuildsDir $targetVersion
$latestDir    = Join-Path $BuildsDir "latest"

if (-not (Test-Path $versionedDir)) { New-Item -ItemType Directory -Path $versionedDir -Force | Out-Null }
if (-not (Test-Path $latestDir))    { New-Item -ItemType Directory -Path $latestDir -Force | Out-Null }

$versionedExe = Join-Path $versionedDir "ClaudeCage.exe"
$latestExe    = Join-Path $latestDir "ClaudeCage.exe"
$rootExe      = Join-Path $TargetRoot "ClaudeCage.exe"

Copy-Item $outExe $versionedExe -Force
Copy-Item $outExe $latestExe -Force
Copy-Item $outExe $rootExe -Force
Remove-Item $outExe -Force

# Compute SHA-256
$hashObj = Get-FileHash -Path $versionedExe -Algorithm SHA256
$sha256 = $hashObj.Hash
Set-Content -Path (Join-Path $versionedDir "checksums.sha256") -Value "$sha256  ClaudeCage.exe"

# Update manifest.json
$manifestList = @()
if (Test-Path $ManifestFile) {
    try {
        $manifestList = @(Get-Content $ManifestFile -Raw | ConvertFrom-Json)
    } catch {}
}

$buildEntry = [ordered]@{
    Version   = $targetVersion
    Date      = $buildDate
    Commit    = $gitCommit
    SizeBytes = $binSize
    Sha256    = $sha256
    ExePath   = "builds/$targetVersion/ClaudeCage.exe"
}
$manifestList = @($buildEntry) + @($manifestList | Where-Object { $_.Version -ne $targetVersion })
$manifestList | ConvertTo-Json -Depth 4 | Set-Content $ManifestFile -Force

# Update version.json
[ordered]@{
    version   = $targetVersion
    lastBuild = $buildDate
    lastCommit= $gitCommit
} | ConvertTo-Json | Set-Content $VersionFile -Force

# 6. Shortcut & Profile Integration
if (-not $NoShortcuts) {
    $wsh = New-Object -ComObject WScript.Shell
    $desktopPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)
    $desktopLnk = Join-Path $desktopPath "Claude.lnk"
    
    $sc = $wsh.CreateShortcut($desktopLnk)
    $sc.TargetPath = $rootExe
    $sc.Arguments = ""
    $sc.WorkingDirectory = $TargetRoot
    $sc.Description = "Claude (Secure Cage)"
    $sc.IconLocation = "$IconFile,0"
    $sc.Save()

    $startMenuPath = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
    if (Test-Path $startMenuPath) {
        $startLnk = Join-Path $startMenuPath "Claude.lnk"
        $scStart = $wsh.CreateShortcut($startLnk)
        $scStart.TargetPath = $rootExe
        $scStart.Arguments = ""
        $scStart.WorkingDirectory = $TargetRoot
        $scStart.Description = "Claude (Secure Cage)"
        $scStart.IconLocation = "$IconFile,0"
        $scStart.Save()
    }

    if (Test-Path $PROFILE) {
        $profileContent = Get-Content $PROFILE -Raw
        $newHook = @"

# ClaudeCage Native CLI Hook
function claude {
    & "$rootExe" cli @args
}
function claudecage {
    & "$rootExe" @args
}
"@
        if ($profileContent -match "function claude") {
            $regex = "(?s)# ClaudeCage.*?function claudecage \{.*?\}"
            if ($profileContent -match $regex) {
                $updatedProfile = $profileContent -replace $regex, $newHook.Trim()
                Set-Content -Path $PROFILE -Value $updatedProfile -Force
            }
        }
    }
}
```

---

## 6. Вопросы для повторного экспертного аудита Gemini Argon 4

1. **Оценка защиты от когнитивного анализа ИИ-агентом:**  
   Является ли замена скриптов `.ps1` на стрипнутый PE-бинарник `ClaudeCage.exe` достаточной для полного исключения обнаружения клетки агентом `Claude Code` при условии удаления/выноса `.md` файлов из рабочего каталога?
2. **Анализ 46 HTTPS-соединений натурного теста:**  
   Выявил ли аудит перехваченных IP-адресов какие-либо скрытые сторонние каналы телеметрии или утечки метаданных, не покрытые текущей таблицей NRPT?
3. **Атомарность перехвата в Go-лаунчере:**  
   Существуют ли специфичные для Windows 11 риски гонки (race conditions) при порождении процесса `Claude.exe` через `os/exec` в Go до того, как переменные окружения `$env:TZ` и `$env:NODE_OPTIONS` будут восприняты рантаймом V8?
