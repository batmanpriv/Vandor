package checker

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/batmanpriv/Vandor/colors"

	"golang.org/x/time/rate"
)

type CheckerConfig struct {
	TargetsFile    string
	CredsFile      string
	Format         string
	Threads        int
	Timeout        int
	RateLimit      int
	Output         string
	GPUAccel       bool
	SmartDetection bool
	ProxyURL       string
	Debug          bool
	Resume         bool
	OutputFormat   string
	CheckerType    string
}

type Credential struct {
	User string
	Pass string
}

type CheckerResult struct {
	Target       string
	Username     string
	Password     string
	Success      bool
	Type         string
	ResponseTime time.Duration
	Error        string
}

type TargetCred struct {
	Target   string
	Username string
	Password string
}

type Checker struct {
	config   CheckerConfig
	results  chan CheckerResult
	wg       sync.WaitGroup
	client   *http.Client
	stopFlag atomic.Bool
	stats    atomic.Int64
	success  atomic.Int64
	limiter  *rate.Limiter
}

func NewChecker(config CheckerConfig) *Checker {
	maxConns := config.Threads * 2
	if maxConns < 100 {
		maxConns = 100
	}
	if maxConns > 10000 {
		maxConns = 10000
	}

	transport := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:          maxConns,
		MaxIdleConnsPerHost:   config.Threads,
		MaxConnsPerHost:       config.Threads,
		IdleConnTimeout:       30 * time.Second,
		DisableKeepAlives:     false,
		ForceAttemptHTTP2:     true,
		ResponseHeaderTimeout: time.Duration(config.Timeout) * time.Second,
	}

	client := &http.Client{
		Timeout:   time.Duration(config.Timeout+2) * time.Second,
		Transport: transport,
	}

	rateLimit := config.RateLimit
	if rateLimit == 0 {
		rateLimit = 1000
	}
	limiter := rate.NewLimiter(rate.Limit(rateLimit), rateLimit)

	return &Checker{
		config:  config,
		client:  client,
		results: make(chan CheckerResult, 100000),
		limiter: limiter,
	}
}

func (c *Checker) Run() {
	fmt.Printf("\n[CHECKER] Loading targets from: %s\n", c.config.TargetsFile)

	combinations, err := c.loadTargetsWithCreds()
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}

	if len(combinations) == 0 {
		fmt.Printf("[ERROR] No valid combinations found!\n")
		return
	}

	total := len(combinations)
	fmt.Printf("[CHECKER] Total: %d | Threads: %d | Rate: %d/s\n", total, c.config.Threads, c.config.RateLimit)

	outFile, err := os.Create(c.config.Output)
	if err != nil {
		fmt.Printf("[ERROR] Cannot create output file: %v\n", err)
		return
	}
	defer outFile.Close()

	sem := make(chan struct{}, c.config.Threads)
	var completed int64
	startTime := time.Now()

	for _, combo := range combinations {
		if c.stopFlag.Load() {
			break
		}

		c.wg.Add(1)
		sem <- struct{}{}

		go func(tc TargetCred) {
			defer c.wg.Done()
			defer func() { <-sem }()

			c.limiter.Wait(context.Background())

			var result CheckerResult

			switch c.config.CheckerType {
			case "cpanel":
				result = c.checkCPanel(tc.Target, tc.Username, tc.Password)
			case "wordpress":
				result = c.checkWordPress(tc.Target, tc.Username, tc.Password)
			default:
				result = c.checkWordPress(tc.Target, tc.Username, tc.Password)
				if !result.Success {
					result = c.checkCPanel(tc.Target, tc.Username, tc.Password)
				}
			}

			if result.Success {
				c.success.Add(1)
				outputLine := fmt.Sprintf("%s:%s:%s", result.Target, result.Username, result.Password)
				outFile.WriteString(outputLine + "\n")
				fmt.Printf("\n%s[✓] %s | %s:%s%s\n", colors.Green, result.Target, result.Username, result.Password, colors.Reset)
			}

			completedCount := atomic.AddInt64(&completed, 1)
			if completedCount%100 == 0 {
				elapsed := time.Since(startTime)
				rate := float64(completedCount) / elapsed.Seconds()
				fmt.Printf("\r[%d/%d] %d%% | %.0f req/s | Found: %d",
					completedCount, total, int(float64(completedCount)/float64(total)*100),
					rate, c.success.Load())
			}
		}(combo)
	}

	c.wg.Wait()
	elapsed := time.Since(startTime)

	fmt.Printf("\n\n%s========================================%s\n", colors.Cyan, colors.Reset)
	fmt.Printf("%sCHECKER COMPLETE%s\n", colors.Green, colors.Reset)
	fmt.Printf("%sTime:%s   %v\n", colors.Yellow, colors.Reset, elapsed.Round(time.Millisecond))
	fmt.Printf("%sFound:%s  %s%d%s\n", colors.Yellow, colors.Reset, colors.Green, c.success.Load(), colors.Reset)
	fmt.Printf("%sSpeed:%s  %.1f req/s\n", colors.Yellow, colors.Reset, float64(total)/elapsed.Seconds())
	fmt.Printf("%sTotal:%s  %d\n", colors.Yellow, colors.Reset, total)
	fmt.Printf("%s========================================%s\n", colors.Cyan, colors.Reset)
}

func (c *Checker) loadTargetsWithCreds() ([]TargetCred, error) {
	var combinations []TargetCred
	file, err := os.Open(c.config.TargetsFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var target, username, password string

		originalLine := line
		line = strings.TrimPrefix(line, "https://")
		line = strings.TrimPrefix(line, "http://")

		if strings.Contains(line, "|") {
			parts := strings.SplitN(line, "|", 3)
			if len(parts) == 3 {
				target = parts[0]
				username = parts[1]
				password = parts[2]
			} else if len(parts) == 2 {
				target = parts[0]
				credParts := strings.SplitN(parts[1], ":", 2)
				if len(credParts) == 2 {
					username = credParts[0]
					password = credParts[1]
				}
			}
		} else {
			lastColon := strings.LastIndex(line, ":")
			if lastColon != -1 {
				password = line[lastColon+1:]
				remaining := line[:lastColon]

				secondLastColon := strings.LastIndex(remaining, ":")
				if secondLastColon != -1 {
					username = remaining[secondLastColon+1:]
					target = remaining[:secondLastColon]
				} else {
					target = remaining
				}
			}
		}

		if target != "" {
			target = strings.TrimSuffix(target, "/")
			target = strings.TrimSuffix(target, ":")

			if !strings.HasPrefix(target, "http") {
				target = "https://" + target
			}
		}

		if username == "" && strings.Contains(originalLine, ":") {
			parts := strings.SplitN(originalLine, ":", 3)
			if len(parts) == 3 {
				target = parts[0]
				username = parts[1]
				password = parts[2]
			}
		}

		if target != "" && username != "" && password != "" {
			combinations = append(combinations, TargetCred{
				Target:   target,
				Username: username,
				Password: password,
			})
		}
	}

	fmt.Printf("[CHECKER] Loaded %d combinations\n", len(combinations))
	return combinations, nil
}
