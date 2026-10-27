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
	Version   = "v6.3.3"
	BuildDate = "2026-10-27T23:00:00Z"
	Commit    = "development"
)

type IpInfoResponse struct {
	IP       string `json:"ip"`
	City     string `json:"city"`
	Country  string `json:"country"`
	Timezone string `json:"timezone"`
	Org      string `json:"org"`
}

type TzCache struct {
	VpnIP     string    `json:"vpn_ip"`
	Timezone  string    `json:"timezone"`
	Timestamp time.Time `json:"timestamp"`
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

// isForbiddenGeo returns true if the detected country or timezone belongs to restricted regions
func isForbiddenGeo(country, tz string) bool {
	c := strings.ToUpper(strings.TrimSpace(country))
	if c == "RU" || c == "BY" {
		return true
	}
	t := strings.ToLower(strings.TrimSpace(tz))
	forbiddenIndicators := []string{
		"moscow", "minsk", "samara", "yekaterinburg", "novosibirsk",
		"vladivostok", "krasnoyarsk", "volgograd", "omsk", "chelyabinsk",
		"rostov", "ufa", "kazan", "irkutsk", "kaliningrad", "belarus", "russia",
	}
	for _, ind := range forbiddenIndicators {
		if strings.Contains(t, ind) {
			return true
		}
	}
	return false
}

func isVpnUp() (bool, string, string) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false, "Unknown", ""
	}
	for _, iface := range interfaces {
		name := strings.ToLower(iface.Name)
		// Ignore virtual pseudo-interfaces like Teredo or ISATAP
		if strings.Contains(name, "teredo") || strings.Contains(name, "isatap") {
			continue
		}
		if iface.Flags&net.FlagUp != 0 {
			if strings.Contains(name, "amnezia") || strings.Contains(name, "wireguard") || strings.Contains(name, "wintun") || strings.Contains(name, "vpn") || strings.Contains(name, "tun") || strings.Contains(name, "tailscale") {
				// Verify interface has assigned, non-link-local IPv4 address
				addrs, err := iface.Addrs()
				if err == nil {
					for _, addr := range addrs {
						if ipnet, ok := addr.(*net.IPNet); ok {
							ip4 := ipnet.IP.To4()
							if ip4 != nil && !ip4.IsLoopback() && !ip4.IsLinkLocalUnicast() && !ip4.IsUnspecified() {
								return true, iface.Name, ip4.String()
							}
						}
					}
				}
				// If interface is UP but has no valid routed IPv4, do NOT return true (prevents false positives)
			}
		}
	}
	return false, "None", ""
}

// resolveVpnTimezone resolves the timezone for the VPN egress IP.
// Returns (timezone, isAllowed). If a forbidden country/city is detected, returns ("", false).
func resolveVpnTimezone(vpnIp string) (string, bool) {
	cageRoot := getCageRoot()
	logsDir := filepath.Join(cageRoot, "logs")
	cacheFile := filepath.Join(logsDir, "tz_cache.json")

	// 1. Check local cache (valid for 1 hour for the same VPN IP)
	if data, err := os.ReadFile(cacheFile); err == nil {
		var cache TzCache
		if json.Unmarshal(data, &cache) == nil {
			if cache.VpnIP == vpnIp && cache.Timezone != "" && time.Since(cache.Timestamp) < 1*time.Hour {
				if isForbiddenGeo("", cache.Timezone) {
					_ = os.Remove(cacheFile)
					return "", false
				}
				return cache.Timezone, true
			}
		}
	}

	// 2. Fetch from ipinfo.io
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("https://ipinfo.io/json")
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		var info IpInfoResponse
		if json.NewDecoder(resp.Body).Decode(&info) == nil && info.Timezone != "" {
			if isForbiddenGeo(info.Country, info.Timezone) {
				_ = os.Remove(cacheFile)
				return "", false
			}
			// Write to cache
			_ = os.MkdirAll(logsDir, 0755)
			newCache := TzCache{
				VpnIP:     vpnIp,
				Timezone:  info.Timezone,
				Timestamp: time.Now(),
			}
			if cData, err := json.Marshal(newCache); err == nil {
				_ = os.WriteFile(cacheFile, cData, 0644)
			}
			return info.Timezone, true
		}
	}

	// 3. Fallback: check if we have any prior valid non-forbidden cached timezone
	if data, err := os.ReadFile(cacheFile); err == nil {
		var cache TzCache
		if json.Unmarshal(data, &cache) == nil && cache.Timezone != "" {
			if !isForbiddenGeo("", cache.Timezone) {
				return cache.Timezone, true
			}
		}
	}

	return "Europe/Amsterdam", true
}

// ensureBinaryCoveredByWfp verifies that targetExe is actively listed in WFP ClaudeKillSwitch rules.
// If missing (e.g. after background Store update), requests elevation to re-sync or aborts (Fail-Closed).
func ensureBinaryCoveredByWfp(targetExe string) bool {
	absTarget, err := filepath.Abs(targetExe)
	if err != nil {
		return false
	}

	psCheck := fmt.Sprintf(`
$target = [System.IO.Path]::GetFullPath('%s')
# Fast-path: query CIM indexed filter directly (< 1s)
$filter = Get-NetFirewallApplicationFilter -Program $target -ErrorAction SilentlyContinue
if ($filter) {
    $rule = $filter | Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Group -eq 'ClaudeKillSwitch' } | Select-Object -First 1
    if ($rule) { exit 0 }
}
# Fallback: scan rules with environment variable expansion
$rules = Get-NetFirewallRule -Group 'ClaudeKillSwitch' -ErrorAction SilentlyContinue
if (-not $rules) { exit 2 }
$filters = $rules | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
foreach ($f in $filters) {
    if ($f.Program -and $f.Program -ne 'Any') {
        try {
            $p = [System.IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($f.Program))
            if ($p -ieq $target) { exit 0 }
        } catch {}
    }
}
exit 3
`, strings.ReplaceAll(absTarget, "'", "''"))

	cmd := exec.Command("powershell.exe", "-NoProfile", "-Command", psCheck)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Run(); err == nil {
		return true
	}

	// Target not covered: trigger elevation for Sync-ClaudeFirewall.ps1 -Enforce
	fmt.Println("[!] Security verification: Binary is not yet covered by active firewall policy.")
	fmt.Println("    Requesting Administrator privileges to enforce atomic WFP rules...")
	syncScript := filepath.Join(getCageRoot(), "Sync-ClaudeFirewall.ps1")
	elevateCmd := fmt.Sprintf(`Start-Process powershell.exe -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File "%s" -Enforce' -Verb RunAs -Wait`, syncScript)
	uac := exec.Command("powershell.exe", "-NoProfile", "-Command", elevateCmd)
	_ = uac.Run()

	// Re-verify strictly (Fail-Closed)
	recheck := exec.Command("powershell.exe", "-NoProfile", "-Command", psCheck)
	recheck.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return recheck.Run() == nil
}

// terminateStaleClaudeProcesses waits up to 3 seconds for all claude.exe processes to fully terminate
// to prevent SingleInstanceLock pipe collisions.
func terminateStaleClaudeProcesses() {
	killCmd := exec.Command("taskkill", "/F", "/IM", "claude.exe", "/T")
	killCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = killCmd.Run()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		checkCmd := exec.Command("tasklist", "/FI", "IMAGENAME eq claude.exe", "/NH")
		checkCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		out, err := checkCmd.Output()
		if err != nil || !strings.Contains(strings.ToLower(string(out)), "claude.exe") {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
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

	// 1. Order-of-Operations: Verify host executable WFP coverage BEFORE opening any network sockets
	selfExe, err := os.Executable()
	if err == nil {
		if !ensureBinaryCoveredByWfp(selfExe) {
			fmt.Println("[!] Security verification failed: Host binary is not covered by network isolation policy. Aborting.")
			return 1
		}
	}

	// 2. Locate Target Executable and verify WFP coverage
	claudeExe := findClaudeDesktopExe()
	if claudeExe == "" {
		fmt.Println("[!] Error: Claude Desktop executable not found on system!")
		return 1
	}

	if !ensureBinaryCoveredByWfp(claudeExe) {
		fmt.Println("[!] Security verification failed: Target binary is not covered by network isolation policy. Aborting.")
		return 1
	}

	// 3. Terminate stale background processes with lock polling
	terminateStaleClaudeProcesses()

	// 4. Verify VPN tunnel status
	vpnActive, vpnName, vpnIp := isVpnUp()
	if !vpnActive {
		fmt.Println("[!] [FAIL-CLOSED] No active VPN tunnel detected.")
		fmt.Println("    Claude will run in strict OFFLINE mode.")
	} else {
		fmt.Printf("[+] Active network tunnel verified: %s (%s)\n", vpnName, vpnIp)
	}

	// 5. Resolve VPN Timezone with local caching and Geo-Fail-Closed verification
	// (Safe to query ipinfo.io: host binary is strictly bound by WFP)
	tz := "Europe/Amsterdam"
	if vpnActive {
		var ok bool
		tz, ok = resolveVpnTimezone(vpnIp)
		if !ok {
			fmt.Println("[CRITICAL ALERT] [FAIL-CLOSED] Egress IP is located in a restricted geographic region!")
			fmt.Println("                 Execution aborted to prevent account suspension.")
			return 1
		}
	}

	// 6. Build Unified Anti-Fraud Environment (includes NODE_OPTIONS for child MCP servers)
	envMap := map[string]string{
		"TZ":                       tz,
		"LANG":                     "en_US.UTF-8",
		"LC_ALL":                   "en_US.UTF-8",
		"NODE_OPTIONS":             "--dns-result-order=ipv4first",
		"ELECTRON_ENABLE_LOGGING":  "false",
		"PATH":                     cageBin + ";" + os.Getenv("PATH"),
	}

	electronFlags := []string{
		"--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
		"--webrtc-ip-handling-policy=disable_non_proxied_udp",
		"--enforce-webrtc-ip-permission-check",
		"--enable-features=WebRtcHideLocalIpsWithMdns",
		"--disable-features=AsyncDns,BuiltInDnsClient,DnsOverHttpsUpgrade",
		"--disable-quic",
		"--disable-component-update",
		"--disable-domain-reliability",
		"--no-pings",
		"--lang=en-US",
		"--accept-lang=en-US,en",
		"--disable-background-networking",
	}

	cmd := exec.Command(claudeExe, electronFlags...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: false}

	// Construct explicit environment block
	cmdEnv := os.Environ()
	for k, v := range envMap {
		cmdEnv = append(cmdEnv, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = cmdEnv

	err = cmd.Start()
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

	// 1. Order-of-Operations: Verify host executable WFP coverage BEFORE opening any network sockets
	selfExe, err := os.Executable()
	if err == nil {
		if !ensureBinaryCoveredByWfp(selfExe) {
			fmt.Println("[!] Security verification failed: Host binary is not covered by network isolation policy. Aborting.")
			return 1
		}
	}

	// 2. Locate Claude Code CLI binary and verify WFP coverage
	claudeCliExe := findClaudeCliExe()
	if claudeCliExe == "" {
		fmt.Println("[!] Error: Claude Code CLI binary not found in npm node_modules!")
		return 1
	}

	if !ensureBinaryCoveredByWfp(claudeCliExe) {
		fmt.Println("[!] Security verification failed: Target binary is not covered by network isolation policy. Aborting.")
		return 1
	}

	// 3. Verify VPN tunnel status
	vpnActive, _, vpnIp := isVpnUp()
	tz := "Europe/Amsterdam"
	if vpnActive {
		var ok bool
		tz, ok = resolveVpnTimezone(vpnIp)
		if !ok {
			fmt.Println("[CRITICAL ALERT] [FAIL-CLOSED] Egress IP is located in a restricted geographic region!")
			fmt.Println("                 Execution aborted to prevent account suspension.")
			return 1
		}
	}

	envMap := map[string]string{
		"TZ":           tz,
		"LANG":         "en_US.UTF-8",
		"LC_ALL":       "en_US.UTF-8",
		"NODE_OPTIONS": "--dns-result-order=ipv4first",
		"PATH":         cageBin + ";" + os.Getenv("PATH"),
	}

	cmd := exec.Command(claudeCliExe, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmdEnv := os.Environ()
	for k, v := range envMap {
		cmdEnv = append(cmdEnv, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = cmdEnv

	err = cmd.Run()
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
		fmt.Printf("ClaudeCage Unified Core (%s)\n\n", Version)
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
