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
	Version   = "v6.3.0"
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
		// If running inside builds/vX or builds/latest, find ClaudeCage root
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
	// 1. Try WindowsApps MSIX path
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

	// 2. Standard Win32 paths
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

	// Terminate stale background processes
	terminateStaleClaudeProcesses()

	// Resolve VPN Timezone
	tz := "Europe/Amsterdam"
	if vpnActive {
		tz = resolveVpnTimezone()
	}

	// Prepare Anti-Fraud environment
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
		// Default double-click action: Launch Claude Desktop
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
		// If unknown arg, check if user passed CLI flags directly (e.g. ClaudeCage.exe --version or -p)
		if strings.HasPrefix(subCmd, "-") {
			os.Exit(runCliMode(os.Args[1:]))
		}
		fmt.Printf("Unknown command: %s. Use 'ClaudeCage.exe help' for usage.\n", subCmd)
		os.Exit(1)
	}
}
