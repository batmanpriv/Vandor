package honeypot

import (
	"context"
	"strconv"
	"fmt"
	"net"
	"strings"
	"time"
	"sync"
)

var honeypotSignatures = []string{
	"cowrie", "kippo", "honeypot", "honey", "fake", "sandbox",
	"pot", "deception", "trap", "canary", "dionaea", "glastopf",
	"conpot", "elasticpot", "heralding", "ipphone", "mailoney",
	"rdpy", "snake", "tanner", "wordpot", "pentbox", "honeyd",
	"laurel", "t-pot", "modernhoneypot", "snare", "tanner",
}

var honeypotIPs = map[string]bool{
	"1.1.1.1": true,
	"2.2.2.2": true,
}

type HoneypotAnalysis struct {
	IsHoneypot   bool     `json:"is_honeypot"`
	Confidence   float64  `json:"confidence"`
	Reason       string   `json:"reason"`
	Signatures   []string `json:"signatures"`
	ResponseTime int64    `json:"response_time_ms"`
	BannerHash   string   `json:"banner_hash"`
}

func DetectHoneypot(host, port string, banner string, timeout int) HoneypotAnalysis {
	analysis := HoneypotAnalysis{
		IsHoneypot: false,
		Confidence: 0.0,
		Signatures: []string{},
	}
	
	var wg sync.WaitGroup
	var mu sync.Mutex
	
	bannerLower := strings.ToLower(banner)
	
	for _, sig := range honeypotSignatures {
		if strings.Contains(bannerLower, sig) {
			analysis.Signatures = append(analysis.Signatures, sig)
			analysis.Confidence += 0.25
		}
	}
	
	if strings.Contains(bannerLower, "ssh-2.0-") && strings.Contains(bannerLower, "libssh") {
		analysis.Confidence += 0.15
		analysis.Signatures = append(analysis.Signatures, "libssh_default")
	}
	
	if strings.Contains(bannerLower, "dropbear") {
		analysis.Confidence -= 0.2
	}
	
	if strings.Contains(bannerLower, "openssh") {
		analysis.Confidence -= 0.1
	}
	
	wg.Add(4)
	
	go func() {
		defer wg.Done()
		score := testProtocolMismatch(host, port, timeout)
		mu.Lock()
		analysis.Confidence += score
		if score > 0 {
			analysis.Signatures = append(analysis.Signatures, "protocol_mismatch")
		}
		mu.Unlock()
	}()
	
	go func() {
		defer wg.Done()
		score, rt := testResponseTime(host, port, timeout)
		mu.Lock()
		analysis.Confidence += score
		analysis.ResponseTime = rt
		if score > 0 {
			analysis.Signatures = append(analysis.Signatures, "slow_response")
		}
		mu.Unlock()
	}()
	
	go func() {
		defer wg.Done()
		score, hash := testBannerConsistency(host, port, timeout)
		mu.Lock()
		analysis.Confidence += score
		analysis.BannerHash = hash
		if score > 0 {
			analysis.Signatures = append(analysis.Signatures, "inconsistent_banner")
		}
		mu.Unlock()
	}()
	
	go func() {
		defer wg.Done()
		score := testMultipleConnections(host, port, timeout)
		mu.Lock()
		analysis.Confidence += score
		if score > 0 {
			analysis.Signatures = append(analysis.Signatures, "connection_limits")
		}
		mu.Unlock()
	}()
	
	wg.Wait()
	
	analysis.Confidence += testTCPTimestamp(host, port, timeout)
	analysis.Confidence += testPortScanBehavior(host, port, timeout)
	
	if isKnownHoneypotIP(host) {
		analysis.Confidence += 0.5
		analysis.Signatures = append(analysis.Signatures, "known_honeypot_ip")
	}
	
	if analysis.Confidence > 0.8 {
		analysis.IsHoneypot = true
		analysis.Reason = "Critical confidence honeypot detection"
	} else if analysis.Confidence > 0.6 {
		analysis.IsHoneypot = true
		analysis.Reason = "High confidence honeypot detection"
	} else if analysis.Confidence > 0.35 {
		analysis.Reason = "Possible honeypot"
	} else {
		analysis.Reason = "Likely genuine service"
	}
	
	if analysis.Confidence > 1.0 {
		analysis.Confidence = 1.0
	}
	if analysis.Confidence < 0.0 {
		analysis.Confidence = 0.0
	}
	
	return analysis
}

func testProtocolMismatch(host, port string, timeout int) float64 {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return 0.0
	}
	defer conn.Close()
	
	conn.SetWriteDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	fmt.Fprintf(conn, "SSH-2.0-Test\r\n")
	
	conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return 0.0
	}
	
	if n > 0 {
		response := strings.ToLower(string(buf[:n]))
		mismatchPatterns := []string{
			"protocol mismatch", "bad protocol", "invalid protocol",
			"unrecognized protocol", "protocol error",
		}
		for _, pattern := range mismatchPatterns {
			if strings.Contains(response, pattern) {
				return 0.25
			}
		}
	}
	return 0.0
}

func testResponseTime(host, port string, timeout int) (float64, int64) {
	start := time.Now()
	
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return 0.0, 0
	}
	defer conn.Close()
	
	conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	buf := make([]byte, 256)
	_, err = conn.Read(buf)
	
	elapsed := time.Since(start)
	rt := elapsed.Milliseconds()
	
	if err == nil && elapsed > 2*time.Second {
		return 0.2, rt
	}
	if err == nil && elapsed < 10*time.Millisecond {
		return 0.1, rt
	}
	return 0.0, rt
}

func testBannerConsistency(host, port string, timeout int) (float64, string) {
	var banners []string
	var hashes []string
	
	for i := 0; i < 5; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
		
		var dialer net.Dialer
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
		if err != nil {
			cancel()
			return 0.0, ""
		}
		
		conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
		buf := make([]byte, 512)
		n, err := conn.Read(buf)
		conn.Close()
		cancel()
		
		if err != nil || n == 0 {
			return 0.0, ""
		}
		
		banner := strings.TrimSpace(string(buf[:n]))
		banners = append(banners, banner)
		hashes = append(hashes, simpleHash(banner))
		
		time.Sleep(200 * time.Millisecond)
	}
	
	uniqueHashes := make(map[string]bool)
	for _, h := range hashes {
		uniqueHashes[h] = true
	}
	
	if len(uniqueHashes) > 2 {
		return 0.35, hashes[0]
	}
	if len(uniqueHashes) > 1 {
		return 0.2, hashes[0]
	}
	return 0.0, hashes[0]
}

func testMultipleConnections(host, port string, timeout int) float64 {
	maxConcurrent := 10
	successCount := 0
	
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrent)
	
	for i := 0; i < 50; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
			defer cancel()
			
			var dialer net.Dialer
			conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
			if err != nil {
				return
			}
			conn.Close()
			successCount++
		}()
	}
	wg.Wait()
	
	if successCount < 40 {
		return 0.3
	}
	return 0.0
}

func testTCPTimestamp(host, port string, timeout int) float64 {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), time.Duration(timeout)*time.Second)
	if err != nil {
		return 0.0
	}
	defer conn.Close()
	
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return 0.0
	}
	
	tcpConn.SetNoDelay(true)
	
	start := time.Now()
	for i := 0; i < 10; i++ {
		fmt.Fprintf(conn, "\n")
		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		buf := make([]byte, 1)
		conn.Read(buf)
	}
	elapsed := time.Since(start)
	
	if elapsed > 5*time.Second {
		return 0.15
	}
	return 0.0
}

func testPortScanBehavior(host, port string, timeout int) float64 {
	closedPort := 65432
	openPort := 22
	
	var wg sync.WaitGroup
	var closedOpen, openOpen bool
	
	wg.Add(2)
	
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
		defer cancel()
		var dialer net.Dialer
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(closedPort)))
		if err == nil {
			conn.Close()
			closedOpen = true
		}
	}()
	
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
		defer cancel()
		var dialer net.Dialer
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(openPort)))
		if err == nil {
			conn.Close()
			openOpen = true
		}
	}()
	
	wg.Wait()
	
	if closedOpen && !openOpen {
		return 0.4
	}
	if closedOpen {
		return 0.2
	}
	return 0.0
}

func testBannerGrabConsistency(host, port string, timeout int) float64 {
	var banners []string
	
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
		defer cancel()
		
		var dialer net.Dialer
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
		if err != nil {
			return 0.0
		}
		
		conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
		buf := make([]byte, 256)
		n, err := conn.Read(buf)
		conn.Close()
		
		if err != nil || n == 0 {
			return 0.0
		}
		
		banners = append(banners, strings.TrimSpace(string(buf[:n])))
		time.Sleep(500 * time.Millisecond)
	}
	
	if banners[0] != banners[1] || banners[1] != banners[2] {
		return 0.25
	}
	return 0.0
}

func isKnownHoneypotIP(host string) bool {
	if honeypotIPs[host] {
		return true
	}
	
	privateIPRanges := []string{
		"10.", "172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
		"172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
		"172.30.", "172.31.", "192.168.",
	}
	for _, prefix := range privateIPRanges {
		if strings.HasPrefix(host, prefix) {
			return false
		}
	}
	return false
}

func simpleHash(s string) string {
	var hash uint32
	for i := 0; i < len(s); i++ {
		hash = hash*31 + uint32(s[i])
	}
	return fmt.Sprintf("%x", hash)
}

func init() {
	honeypotIPs["185.110.188.1"] = true
	honeypotIPs["94.200.0.1"] = true
	honeypotIPs["3.120.0.1"] = true
	honeypotIPs["13.40.0.1"] = true
	honeypotIPs["3.224.0.1"] = true
	honeypotIPs["13.228.0.1"] = true
	honeypotIPs["13.112.0.1"] = true
}
