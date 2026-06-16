package webinferno

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"golang.org/x/time/rate"
)

type IntelligenceLevel int

const (
	LevelDumb IntelligenceLevel = iota
	LevelSmart
	LevelGenius
	LevelGod
)

type ContentType string

const (
	FormURLEncoded ContentType = "application/x-www-form-urlencoded"
	JSON           ContentType = "application/json"
	XML            ContentType = "application/xml"
	Multipart      ContentType = "multipart/form-data"
)

type VariableSource struct {
	Type      string
	Values    []string
	FilePath  string
	Mutations []string
}

type SuccessCriterion struct {
	Type  string
	Value string
}

type FailureCriterion struct {
	Type  string
	Value string
}

type DataExtractor struct {
	Name       string
	Type       string
	Pattern    string
	StartToken string
	EndToken   string
	StoreAs    string
}

type RequestTemplate struct {
	Method   string
	URL      string
	Headers  map[string]string
	Body     string
	BodyType string
}

type InfernoResult struct {
	Timestamp    time.Time
	URL          string
	Variables    map[string]string
	StatusCode   int
	ResponseTime time.Duration
	ResponseLen  int
	Extracted    map[string]string
	Success      bool
	Error        string
}

type AuthConfig struct {
	Type      string
	Username  string
	Password  string
	Token     string
	TokenFile string
	Bearer    string
}

type OAuth2Config struct {
	ClientID     string
	ClientSecret string
	TokenURL     string
	Scope        string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

type GraphQLQuery struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables,omitempty"`
}

type GraphQLResponse struct {
	Data   interface{}   `json:"data"`
	Errors []interface{} `json:"errors,omitempty"`
}

type WebInfernoConfig struct {
	RequestFile          string
	Method               string
	Body                 string
	Variables            map[string]VariableSource
	SuccessCriteria      []SuccessCriterion
	FailureCriteria      []FailureCriterion
	Extractors           []DataExtractor
	Intelligence         IntelligenceLevel
	AutoDetectTokens     bool
	EvasionLevel         int
	RandomDelays         bool
	OutputSuccess        string
	OutputFail           string
	OutputTokens         string
	Timeout              int
	Threads              int
	MaxRetries           int
	RateLimit            int
	FollowRedirects      bool
	MaxRedirects         int
	DynamicToken         bool
	TokenURL             string
	TokenMethod          string
	TokenStart           string
	TokenEnd             string
	TokenRefreshInterval int
	TokenField           string
	ProxyURL             string
	Debug                bool
	Auth                 AuthConfig
	OAuth                OAuth2Config
	FuzzPositions        []int
	FuzzPayloads         []string
	ClusterNodes         []string
	WebSocketURL         string
	GraphQLEndpoint      string
	AdaptiveRateLimit bool
	OutputFormat string
}

type Session struct {
	Cookies   []*http.Cookie
	Headers   map[string]string
	LastLogin time.Time
}

type PatternLearner struct {
	successPatterns map[string]int
	failurePatterns map[string]int
	mu              sync.RWMutex
}

func NewPatternLearner() *PatternLearner {
	return &PatternLearner{
		successPatterns: make(map[string]int),
		failurePatterns: make(map[string]int),
	}
}

func (pl *PatternLearner) Learn(response string, success bool) {
	pl.mu.Lock()
	defer pl.mu.Unlock()

	words := strings.Fields(response)
	for _, word := range words {
		if len(word) > 3 {
			word = strings.ToLower(word)
			if success {
				pl.successPatterns[word]++
			} else {
				pl.failurePatterns[word]++
			}
		}
	}
}

func (pl *PatternLearner) Predict(response string) bool {
	pl.mu.RLock()
	defer pl.mu.RUnlock()

	score := 0
	words := strings.Fields(response)
	for _, word := range words {
		word = strings.ToLower(word)
		if pl.successPatterns[word] > pl.failurePatterns[word]*2 {
			score++
		}
		if pl.failurePatterns[word] > pl.successPatterns[word]*2 {
			score--
		}
	}
	return score > 0
}

type AdaptiveLimiter struct {
	successRate float64
	currentRate int
	minRate     int
	maxRate     int
	mu          sync.RWMutex
}

func NewAdaptiveLimiter(minRate, maxRate int) *AdaptiveLimiter {
	return &AdaptiveLimiter{
		successRate: 0.5,
		currentRate: (minRate + maxRate) / 2,
		minRate:     minRate,
		maxRate:     maxRate,
	}
}

func (al *AdaptiveLimiter) Adjust(success bool) {
	al.mu.Lock()
	defer al.mu.Unlock()

	if success {
		al.successRate = al.successRate*0.9 + 0.1
	} else {
		al.successRate = al.successRate * 0.9
	}

	if al.successRate > 0.8 && al.currentRate < al.maxRate {
		al.currentRate++
	} else if al.successRate < 0.3 && al.currentRate > al.minRate {
		al.currentRate--
	}
}

func (al *AdaptiveLimiter) GetRate() int {
	al.mu.RLock()
	defer al.mu.RUnlock()
	return al.currentRate
}

type ClusterNode struct {
	ID       string
	Address  string
	Jobs     int
	Status   string
	LastSeen time.Time
}

type Report struct {
	StartTime   time.Time
	EndTime     time.Time
	TotalReqs   int64
	SuccessReqs int64
	FailedReqs  int64
	UniqueVars  map[string][]string
	SuccessVars map[string][]string
	ErrorCounts map[string]int
}

type WebInferno struct {
	config          WebInfernoConfig
	client          *http.Client
	limiter         *rate.Limiter
	adaptiveLimiter *AdaptiveLimiter
	results         chan InfernoResult
	tokens          map[string]string
	session         map[string]string
	sessionCookies  map[string]*http.Cookie
	stats           atomic.Int64
	successCount    atomic.Int64
	failCount       atomic.Int64
	mu              sync.RWMutex
	stopFlag        atomic.Bool
	wg              sync.WaitGroup
	userAgent       string
	patternLearner  *PatternLearner
	nodes           []*ClusterNode
	startTime       time.Time
	oAuthToken      string
	oAuthExpiry     time.Time
	wsConn          *websocket.Conn
}

func NewWebInferno(config WebInfernoConfig) *WebInferno {
	jar, _ := cookiejar.New(nil)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:    100,
		IdleConnTimeout: 90 * time.Second,
	}

	if config.ProxyURL != "" {
		proxyURL, _ := url.Parse(config.ProxyURL)
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	client := &http.Client{
		Jar:       jar,
		Timeout:   time.Duration(config.Timeout) * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !config.FollowRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) >= config.MaxRedirects {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

    limiter := rate.NewLimiter(rate.Limit(config.RateLimit), config.RateLimit)
    
    var adaptiveLimiter *AdaptiveLimiter
    if config.AdaptiveRateLimit {
        adaptiveLimiter = NewAdaptiveLimiter(config.RateLimit/10, config.RateLimit)
    }

	nodes := make([]*ClusterNode, 0)
	for _, addr := range config.ClusterNodes {
		nodes = append(nodes, &ClusterNode{
			ID:       uuid.New().String(),
			Address:  addr,
			Status:   "idle",
			LastSeen: time.Now(),
		})
	}

	return &WebInferno{
		config:          config,
		client:          client,
		limiter:         limiter,
		adaptiveLimiter: adaptiveLimiter,
		results:         make(chan InfernoResult, 10000),
		tokens:          make(map[string]string),
		session:         make(map[string]string),
		sessionCookies:  make(map[string]*http.Cookie),
		userAgent:       randomUserAgent(),
		patternLearner:  NewPatternLearner(),
		nodes:           nodes,
		startTime:       time.Now(),
	}
}

func (wi *WebInferno) Run() {
	wi.printHeader()

	if wi.config.WebSocketURL != "" {
		wi.runWebSocketAttack()
		return
	}

	if wi.config.GraphQLEndpoint != "" {
		wi.runGraphQLAttack()
		return
	}

	template, err := wi.loadTemplate()
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}

	combinations := wi.generateCombinations()
	total := len(combinations)

	fmt.Printf("[TARGET] %s\n", template.URL)
	fmt.Printf("[METHOD] %s | THREADS: %d | RATE: %d/s\n", template.Method, wi.config.Threads, wi.config.RateLimit)
	fmt.Printf("[COMBINATIONS] %d\n", total)

	if wi.config.Auth.Type != "" {
		fmt.Printf("[AUTH] Type: %s\n", wi.config.Auth.Type)
	}

	if wi.config.OAuth.ClientID != "" {
		fmt.Printf("[OAUTH] Client ID: %s\n", wi.config.OAuth.ClientID)
		go wi.refreshOAuthTokenPeriodically()
	}

	if len(wi.config.FuzzPayloads) > 0 {
		fmt.Printf("[FUZZ] Payloads: %d\n", len(wi.config.FuzzPayloads))
	}

	if len(wi.nodes) > 0 {
		fmt.Printf("[CLUSTER] Nodes: %d\n", len(wi.nodes))
		wi.distributeWork(combinations)
		return
	}

	if wi.config.AutoDetectTokens {
		wi.detectInitialTokens(template)
	}

	if wi.config.DynamicToken {
		go wi.refreshTokenPeriodically()
	}

	sem := make(chan struct{}, wi.config.Threads)
	var completed int32

	for i, vars := range combinations {
		if wi.stopFlag.Load() {
			break
		}

		wi.wg.Add(1)
		sem <- struct{}{}

		go func(idx int, v map[string]string) {
			defer wi.wg.Done()
			defer func() { <-sem }()
			var currentRate int
            if wi.adaptiveLimiter != nil {
                currentRate := wi.adaptiveLimiter.GetRate()
                wi.limiter.SetLimit(rate.Limit(currentRate))
            } else {
                wi.limiter.SetLimit(rate.Limit(float64(wi.config.RateLimit)))
            }

            wi.limiter.Wait(context.Background())

			if wi.config.RandomDelays {
				time.Sleep(time.Duration(rand.Intn(2000)) * time.Millisecond)
			}

			result := wi.execute(template, v, idx)
			wi.results <- result

			if wi.adaptiveLimiter != nil {
				wi.adaptiveLimiter.Adjust(result.Success)
			}

			c := atomic.AddInt32(&completed, 1)
			if c%50 == 0 || int(c) == total {
				pct := float64(c) / float64(total) * 100
				fmt.Printf("\r[PROGRESS] %.1f%% (%d/%d) | Rate: %d/s", pct, c, total, currentRate)
			}
		}(i, vars)
	}

	wi.wg.Wait()
	close(wi.results)
	wi.printStats()
	wi.generateReport()
}

func (wi *WebInferno) execute(template *RequestTemplate, vars map[string]string, idx int) InfernoResult {
	start := time.Now()

	if wi.config.DynamicToken && idx%wi.config.TokenRefreshInterval == 0 {
		wi.refreshToken()
	}

	req := wi.buildRequest(template, vars)
	wi.applyAuth(req)
	wi.applyEvasion(req)

	resp, body, err := wi.send(req)
	elapsed := time.Since(start)

	result := InfernoResult{
		Timestamp:    time.Now(),
		URL:          template.URL,
		Variables:    vars,
		StatusCode:   0,
		ResponseTime: elapsed,
		ResponseLen:  0,
		Extracted:    make(map[string]string),
		Success:      false,
	}

	if err != nil {
		result.Error = err.Error()
		wi.stats.Add(1)
		wi.failCount.Add(1)
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.ResponseLen = len(body)

	wi.saveSession(resp)

	if wi.config.Intelligence >= LevelSmart {
		wi.patternLearner.Learn(body, result.Success)
	}

	if wi.config.Intelligence >= LevelGenius && len(wi.config.SuccessCriteria) == 0 {
		result.Success = wi.patternLearner.Predict(body)
	} else {
		result.Success = wi.checkSuccess(body, resp.StatusCode)
	}

	for _, ex := range wi.config.Extractors {
		if value := wi.extractAdvanced(body, ex); value != "" {
			result.Extracted[ex.Name] = value
			wi.mu.Lock()
			wi.tokens[ex.StoreAs] = value
			wi.mu.Unlock()
			wi.saveToken(ex.Name, value, vars)
		}
	}

	if len(wi.config.FuzzPayloads) > 0 {
		wi.fuzzRequest(template, vars, body)
	}

	if result.Success {
		wi.successCount.Add(1)
		if wi.config.OutputSuccess != "" {
			wi.saveResult(result)
		}
	} else {
		wi.failCount.Add(1)
	}

	wi.stats.Add(1)
	return result
}

func (wi *WebInferno) buildRequest(template *RequestTemplate, vars map[string]string) *http.Request {
	urlStr := wi.replaceVars(template.URL, vars)
	body := wi.replaceVars(template.Body, vars)

	contentType := wi.detectContentType(body)

	if contentType == JSON && body != "" {
		var jsonBody interface{}
		if err := json.Unmarshal([]byte(body), &jsonBody); err == nil {
			jsonBytes, _ := json.Marshal(jsonBody)
			body = string(jsonBytes)
		}
	} else if contentType == XML && body != "" {
		var xmlBody interface{}
		if err := xml.Unmarshal([]byte(body), &xmlBody); err == nil {
			xmlBytes, _ := xml.Marshal(xmlBody)
			body = string(xmlBytes)
		}
	} else if contentType == Multipart && body != "" {
		var buf bytes.Buffer
		writer := multipart.NewWriter(&buf)
		parts := strings.Split(body, "&")
		for _, part := range parts {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 {
				writer.WriteField(kv[0], kv[1])
			}
		}
		writer.Close()
		body = buf.String()
		template.Headers["Content-Type"] = writer.FormDataContentType()
	} else if strings.Contains(body, ",") && !strings.Contains(body, "&") {
		body = strings.ReplaceAll(body, ",", "&")
	}

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, _ := http.NewRequest(template.Method, urlStr, bodyReader)

	for k, v := range template.Headers {
		req.Header.Set(k, wi.replaceVars(v, vars))
	}

	if template.Method == "POST" && body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", string(contentType))
	}

	req.Header.Set("User-Agent", wi.userAgent)

	wi.mu.RLock()
	for k, v := range wi.session {
		req.Header.Set(k, v)
	}
	for _, c := range wi.sessionCookies {
		req.AddCookie(c)
	}
	wi.mu.RUnlock()

	return req
}

func (wi *WebInferno) detectContentType(body string) ContentType {
	body = strings.TrimSpace(body)
	if strings.HasPrefix(body, "{") || strings.HasPrefix(body, "[") {
		return JSON
	}
	if strings.HasPrefix(body, "<") {
		return XML
	}
	if strings.Contains(body, "------WebKitFormBoundary") {
		return Multipart
	}
	return FormURLEncoded
}

func (wi *WebInferno) applyAuth(req *http.Request) {
	switch wi.config.Auth.Type {
	case "basic":
		req.SetBasicAuth(wi.config.Auth.Username, wi.config.Auth.Password)
	case "bearer":
		if wi.config.Auth.Bearer != "" {
			req.Header.Set("Authorization", "Bearer "+wi.config.Auth.Bearer)
		} else if wi.config.Auth.Token != "" {
			req.Header.Set("Authorization", "Bearer "+wi.config.Auth.Token)
		}
	case "token":
		req.Header.Set("X-API-Key", wi.config.Auth.Token)
	}
}

func (wi *WebInferno) saveSession(resp *http.Response) {
	if cookies := resp.Cookies(); len(cookies) > 0 {
		wi.mu.Lock()
		for _, c := range cookies {
			wi.sessionCookies[c.Name] = c
		}
		wi.mu.Unlock()
	}
}

func (wi *WebInferno) extractAdvanced(body string, ex DataExtractor) string {
	switch ex.Type {
	case "regex":
		re := regexp.MustCompile(ex.Pattern)
		if matches := re.FindStringSubmatch(body); len(matches) > 1 {
			return matches[1]
		}
	case "regex_named":
		re := regexp.MustCompile(ex.Pattern)
		matches := re.FindStringSubmatch(body)
		results := make(map[string]string)
		for i, name := range re.SubexpNames() {
			if i != 0 && name != "" && i < len(matches) {
				results[name] = matches[i]
			}
		}
		if val, ok := results[ex.StoreAs]; ok {
			return val
		}
	case "between":
		start := strings.Index(body, ex.StartToken)
		if start != -1 {
			start += len(ex.StartToken)
			end := strings.Index(body[start:], ex.EndToken)
			if end != -1 {
				return body[start : start+end]
			}
		}
	case "json":
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(body), &data); err == nil {
			if val, ok := data[ex.Pattern]; ok {
				return fmt.Sprintf("%v", val)
			}
		}
	case "xpath":
		if strings.Contains(body, fmt.Sprintf(">%s<", ex.Pattern)) {
			return ex.Pattern
		}
	}
	return ""
}

func (wi *WebInferno) fuzzRequest(template *RequestTemplate, vars map[string]string, response string) {
	for _, payload := range wi.config.FuzzPayloads {
		fuzzedURL := strings.Replace(template.URL, "FUZZ", payload, -1)
		fuzzedBody := strings.Replace(template.Body, "FUZZ", payload, -1)

		fuzzedTemplate := &RequestTemplate{
			Method:   template.Method,
			URL:      fuzzedURL,
			Headers:  template.Headers,
			Body:     fuzzedBody,
			BodyType: template.BodyType,
		}

		req := wi.buildRequest(fuzzedTemplate, vars)
		resp, body, err := wi.send(req)
		if err == nil && resp != nil {
			defer resp.Body.Close()
			if len(body) != len(response) {
				fmt.Printf("[FUZZ] Payload '%s' changed response length: %d -> %d\n",
					payload, len(response), len(body))
			}
		}
	}
}

func (wi *WebInferno) send(req *http.Request) (*http.Response, string, error) {
	var lastErr error

	for attempt := 0; attempt <= wi.config.MaxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(attempt*attempt) * time.Second
			time.Sleep(backoff)
		}

		resp, err := wi.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode == 429 || resp.StatusCode == 503 {
			resp.Body.Close()
			retryAfter := resp.Header.Get("Retry-After")
			if retryAfter != "" {
				if seconds, err := time.ParseDuration(retryAfter + "s"); err == nil {
					time.Sleep(seconds)
				}
			}
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if err != nil {
			lastErr = err
			continue
		}

		if wi.config.AutoDetectTokens {
			wi.extractTokensFromResponse(string(body))
		}

		return resp, string(body), nil
	}

	return nil, "", lastErr
}

func (wi *WebInferno) distributeWork(combinations []map[string]string) {
	perNode := len(combinations) / len(wi.nodes)
	if perNode < 1 {
		perNode = 1
	}

	for i, node := range wi.nodes {
		start := i * perNode
		end := start + perNode
		if end > len(combinations) {
			end = len(combinations)
		}
		if start >= len(combinations) {
			break
		}
		go wi.sendToNode(node, combinations[start:end])
	}
}

func (wi *WebInferno) sendToNode(node *ClusterNode, combinations []map[string]string) {
	node.Status = "busy"
	node.Jobs = len(combinations)
	fmt.Printf("[CLUSTER] Node %s processing %d jobs\n", node.Address, len(combinations))

	for _, vars := range combinations {
		if wi.stopFlag.Load() {
			break
		}

		reqBody, _ := json.Marshal(vars)
		resp, err := http.Post(node.Address+"/api/job", "application/json", bytes.NewReader(reqBody))
		if err != nil {
			fmt.Printf("[CLUSTER] Node %s error: %v\n", node.Address, err)
			continue
		}
		resp.Body.Close()
	}

	node.Status = "idle"
	node.LastSeen = time.Now()
}

func (wi *WebInferno) refreshOAuthTokenPeriodically() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		if err := wi.refreshOAuthToken(); err != nil {
			fmt.Printf("[OAUTH] Token refresh failed: %v\n", err)
		}
	}
}

func (wi *WebInferno) refreshOAuthToken() error {
	if wi.config.OAuth.TokenURL == "" {
		return nil
	}

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", wi.config.OAuth.ClientID)
	data.Set("client_secret", wi.config.OAuth.ClientSecret)
	if wi.config.OAuth.Scope != "" {
		data.Set("scope", wi.config.OAuth.Scope)
	}

	resp, err := http.PostForm(wi.config.OAuth.TokenURL, data)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	if token, ok := result["access_token"].(string); ok {
		wi.oAuthToken = token
		wi.config.Auth.Bearer = token
		if expiresIn, ok := result["expires_in"].(float64); ok {
			wi.oAuthExpiry = time.Now().Add(time.Duration(expiresIn) * time.Second)
		}
		fmt.Printf("[OAUTH] Token refreshed: %s...\n", token[:min(20, len(token))])
	}

	return nil
}

func (wi *WebInferno) runWebSocketAttack() {
	fmt.Printf("[WS] WebSocket attack on %s\n", wi.config.WebSocketURL)

	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	conn, _, err := dialer.Dial(wi.config.WebSocketURL, nil)
	if err != nil {
		fmt.Printf("[WS] Connection failed: %v\n", err)
		return
	}
	defer conn.Close()

	combinations := wi.generateCombinations()
	fmt.Printf("[WS] Testing %d combinations\n", len(combinations))

	for _, vars := range combinations {
		message := wi.replaceVars("", vars)
		if err := conn.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
			fmt.Printf("[WS] Write error: %v\n", err)
			continue
		}

		_, msg, err := conn.ReadMessage()
		if err != nil {
			fmt.Printf("[WS] Read error: %v\n", err)
			continue
		}

		success := wi.checkSuccess(string(msg), 200)
		if success {
			fmt.Printf("[WS] SUCCESS: %v\n", vars)
			wi.saveResult(InfernoResult{
				Timestamp: time.Now(),
				URL:       wi.config.WebSocketURL,
				Variables: vars,
				Success:   true,
			})
		}
	}
}

func (wi *WebInferno) runGraphQLAttack() {
	fmt.Printf("[GQL] GraphQL attack on %s\n", wi.config.GraphQLEndpoint)

	combinations := wi.generateCombinations()

	for _, vars := range combinations {
		query := wi.replaceVars(wi.config.Body, vars)

		gqlQuery := GraphQLQuery{
			Query:     query,
			Variables: make(map[string]interface{}),
		}

		for k, v := range vars {
			gqlQuery.Variables[k] = v
		}

		body, _ := json.Marshal(gqlQuery)
		req, _ := http.NewRequest("POST", wi.config.GraphQLEndpoint, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, respBody, err := wi.send(req)
		if err != nil {
			continue
		}

		var gqlResp GraphQLResponse
		json.Unmarshal([]byte(respBody), &gqlResp)

		success := len(gqlResp.Errors) == 0 && resp.StatusCode == 200
		if success {
			fmt.Printf("[GQL] SUCCESS: %v\n", vars)
			wi.saveResult(InfernoResult{
				Timestamp:  time.Now(),
				URL:        wi.config.GraphQLEndpoint,
				Variables:  vars,
				StatusCode: resp.StatusCode,
				Success:    true,
			})
		}
	}
}

func (wi *WebInferno) refreshTokenPeriodically() {
	if wi.config.TokenRefreshInterval <= 0 {
		wi.config.TokenRefreshInterval = 30
	}

	ticker := time.NewTicker(time.Duration(wi.config.TokenRefreshInterval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if wi.stopFlag.Load() {
			return
		}
		wi.refreshToken()
	}
}

func (wi *WebInferno) generateReport() {
	report := &Report{
		StartTime:   wi.startTime,
		EndTime:     time.Now(),
		TotalReqs:   wi.stats.Load(),
		SuccessReqs: wi.successCount.Load(),
		FailedReqs:  wi.failCount.Load(),
		UniqueVars:  make(map[string][]string),
		SuccessVars: make(map[string][]string),
		ErrorCounts: make(map[string]int),
	}

	htmlContent := wi.generateHTMLReport(report)
	os.WriteFile("webinferno_report.html", []byte(htmlContent), 0644)

	jsonData, _ := json.MarshalIndent(report, "", "  ")
	os.WriteFile("webinferno_report.json", jsonData, 0644)

	fmt.Printf("\n[REPORT] Generated: webinferno_report.html | webinferno_report.json\n")
}

func (wi *WebInferno) generateHTMLReport(report *Report) string {
    duration := report.EndTime.Sub(report.StartTime)
    successRate := float64(0)
    if report.TotalReqs > 0 {
        successRate = float64(report.SuccessReqs) / float64(report.TotalReqs) * 100
    }

    return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Web Inferno Report</title>
    <style>
        body { font-family: Arial; margin: 20px; background: #1e1e1e; color: #ddd; }
        .container { max-width: 1200px; margin: auto; }
        .header { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); padding: 20px; border-radius: 10px; }
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }
        .stat-card { background: #2d2d2d; padding: 15px; border-radius: 8px; text-align: center; }
        .stat-value { font-size: 32px; font-weight: bold; color: #667eea; }
        .success { color: #4caf50; }
        .failed { color: #f44336; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔥 Web Inferno Attack Report</h1>
            <p>Generated: %s | Duration: %s</p>
        </div>
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">%d</div>
                <div>Total Requests</div>
            </div>
            <div class="stat-card">
                <div class="stat-value success">%d</div>
                <div>Successful</div>
            </div>
            <div class="stat-card">
                <div class="stat-value failed">%d</div>
                <div>Failed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">%.1f%%</div>
                <div>Success Rate</div>
            </div>
        </div>
    </div>
</body>
</html>`,
        time.Now().Format("2006-01-02 15:04:05"),
        duration.Round(time.Second),
        report.TotalReqs,
        report.SuccessReqs,
        report.FailedReqs,
        successRate,
    )
}

func (wi *WebInferno) checkSuccess(body string, statusCode int) bool {
    bodyLower := strings.ToLower(body)
    
    if wi.config.Debug {
        fmt.Printf("\n[DEBUG] ========== CHECK SUCCESS ==========\n")
        fmt.Printf("[DEBUG] Response (first 500 chars):\n%s\n", body[:min(len(body), 500)])
        fmt.Printf("[DEBUG] SuccessCriteria (ifin): %+v\n", wi.config.SuccessCriteria)
        fmt.Printf("[DEBUG] FailureCriteria (ifnin): %+v\n", wi.config.FailureCriteria)
    }
  
    if len(wi.config.FailureCriteria) > 0 { 
        for _, c := range wi.config.FailureCriteria {  
            if c.Type == "not_contains" {
                if strings.Contains(bodyLower, strings.ToLower(c.Value)) {
                    if wi.config.Debug {
                        fmt.Printf("[DEBUG] ❌ ifnin FAILED: '%s' found (should NOT be there)\n", c.Value)
                    }
                    return false  
                }
            }
        }
        if wi.config.Debug {
            fmt.Printf("[DEBUG] ✅ ifnin PASSED: '%s' NOT found\n", wi.config.FailureCriteria[0].Value)
        }
        return true  
    }	

    if len(wi.config.SuccessCriteria) > 0 {
        for _, c := range wi.config.SuccessCriteria {
            if c.Type == "contains" {
                if strings.Contains(bodyLower, strings.ToLower(c.Value)) {
                    if wi.config.Debug {
                        fmt.Printf("[DEBUG] ✅ ifin MATCHED: '%s' found\n", c.Value)
                    }
                    return true 
                }
            }
        }
        if wi.config.Debug {
            fmt.Printf("[DEBUG] ❌ ifin NOT MATCHED: none found\n")
        }
        return false 
    }
    
    return statusCode >= 200 && statusCode < 300
}

func (wi *WebInferno) extractTokensFromResponse(body string) {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`name="csrf_token"\s+value="([^"]+)"`),
		regexp.MustCompile(`name="authenticity_token"\s+value="([^"]+)"`),
		regexp.MustCompile(`data-token="([^"]+)"`),
		regexp.MustCompile(`csrf-token" content="([^"]+)"`),
		regexp.MustCompile(`_token":"([^"]+)"`),
		regexp.MustCompile(`"token":"([^"]+)"`),
	}

	wi.mu.Lock()
	for _, re := range patterns {
		if matches := re.FindStringSubmatch(body); len(matches) > 1 {
			wi.tokens["token"] = matches[1]
			break
		}
	}
	wi.mu.Unlock()
}

func (wi *WebInferno) replaceVars(s string, vars map[string]string) string {
	for k, v := range vars {
		s = strings.ReplaceAll(s, "[["+k+"]]", v)
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
		s = strings.ReplaceAll(s, "${"+k+"}", v)
		s = strings.ReplaceAll(s, "$"+k+"$", v)
		s = strings.ReplaceAll(s, "%"+k+"%", url.QueryEscape(v))
		s = strings.ReplaceAll(s, "{"+k+"}", v)
		s = strings.ReplaceAll(s, "("+k+")", v)
	}
	return s
}

func (wi *WebInferno) generateCombinations() []map[string]string {
	if len(wi.config.Variables) == 0 {
		return []map[string]string{{}}
	}

	values := make(map[string][]string)
	for name, src := range wi.config.Variables {
		var list []string

		switch src.Type {
		case "file":
			if data, err := os.ReadFile(src.FilePath); err == nil {
				scanner := bufio.NewScanner(bytes.NewReader(data))
				for scanner.Scan() {
					if line := strings.TrimSpace(scanner.Text()); line != "" && !strings.HasPrefix(line, "#") {
						list = append(list, line)
					}
				}
			}
		case "inline":
			list = src.Values
		}

		for _, m := range src.Mutations {
			for _, v := range list {
				switch m {
				case "uppercase":
					list = append(list, strings.ToUpper(v))
				case "lowercase":
					list = append(list, strings.ToLower(v))
				case "capitalize":
					if len(v) > 0 {
						list = append(list, strings.ToUpper(v[:1])+strings.ToLower(v[1:]))
					}
				case "leet":
					leet := strings.NewReplacer("a", "4", "e", "3", "i", "1", "o", "0", "s", "5", "t", "7")
					list = append(list, leet.Replace(v))
				case "append123":
					list = append(list, v+"123")
				case "prepend123":
					list = append(list, "123"+v)
				case "reverse":
					runes := []rune(v)
					for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
						runes[i], runes[j] = runes[j], runes[i]
					}
					list = append(list, string(runes))
				}
			}
		}

		values[name] = list
	}

	return wi.cartesianProduct(values)
}

func (wi *WebInferno) cartesianProduct(data map[string][]string) []map[string]string {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}

	var results []map[string]string

	var generate func(idx int, current map[string]string)
	generate = func(idx int, current map[string]string) {
		if idx == len(keys) {
			tmp := make(map[string]string)
			for k, v := range current {
				tmp[k] = v
			}
			results = append(results, tmp)
			return
		}

		key := keys[idx]
		for _, val := range data[key] {
			current[key] = val
			generate(idx+1, current)
		}
	}

	generate(0, make(map[string]string))
	return results
}

func (wi *WebInferno) loadTemplate() (*RequestTemplate, error) {
	if strings.HasPrefix(wi.config.RequestFile, "http://") || strings.HasPrefix(wi.config.RequestFile, "https://") {
		return &RequestTemplate{
			Method:   wi.config.Method,
			URL:      wi.config.RequestFile,
			Body:     wi.config.Body,
			BodyType: "raw",
			Headers:  make(map[string]string),
		}, nil
	}

	data, err := os.ReadFile(wi.config.RequestFile)
	if err != nil {
		return nil, err
	}

	content := string(data)
	lines := strings.Split(content, "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty request file")
	}

	first := strings.Fields(lines[0])
	if len(first) < 2 {
		return nil, fmt.Errorf("invalid request format")
	}

	method := first[0]
	path := first[1]

	headers := make(map[string]string)
	var host string
	var bodyStart int

	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			bodyStart = i + 1
			break
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			headers[key] = value
			if strings.ToLower(key) == "host" {
				host = value
			}
		}
	}

	body := ""
	if bodyStart < len(lines) {
		body = strings.Join(lines[bodyStart:], "\n")
	}

	scheme := "http"
	if strings.Contains(content, "https://") || strings.Contains(host, ":443") {
		scheme = "https"
	}

	fullURL := fmt.Sprintf("%s://%s%s", scheme, host, path)

	return &RequestTemplate{
		Method:   method,
		URL:      fullURL,
		Headers:  headers,
		Body:     body,
		BodyType: "raw",
	}, nil
}

func (wi *WebInferno) detectInitialTokens(template *RequestTemplate) {
	req, _ := http.NewRequest(template.Method, template.URL, nil)
	wi.applyAuth(req)
	resp, body, err := wi.send(req)
	if err != nil || resp == nil {
		return
	}
	defer resp.Body.Close()
	wi.extractTokensFromResponse(body)
}

func (wi *WebInferno) refreshToken() {
	if wi.config.TokenURL == "" {
		return
	}

	req, _ := http.NewRequest(wi.config.TokenMethod, wi.config.TokenURL, nil)
	wi.applyAuth(req)
	resp, body, err := wi.send(req)
	if err != nil || resp == nil {
		return
	}
	defer resp.Body.Close()

	var token string
	if wi.config.TokenStart != "" && wi.config.TokenEnd != "" {
		start := strings.Index(body, wi.config.TokenStart)
		if start != -1 {
			start += len(wi.config.TokenStart)
			end := strings.Index(body[start:], wi.config.TokenEnd)
			if end != -1 {
				token = body[start : start+end]
			}
		}
	} else {
		wi.extractTokensFromResponse(body)
		token = wi.tokens["token"]
	}

	if token != "" {
		wi.mu.Lock()
		wi.tokens[wi.config.TokenField] = token
		wi.mu.Unlock()
		fmt.Printf("[TOKEN] Refreshed: %s...\n", token[:min(10, len(token))])
	}
}

func (wi *WebInferno) applyEvasion(req *http.Request) {
	if wi.config.EvasionLevel >= 1 {
		req.Header.Set("User-Agent", randomUserAgent())
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	}

	if wi.config.EvasionLevel >= 2 {
		req.Header.Set("Sec-Ch-Ua", `"Not_A Brand";v="8", "Chromium";v="120"`)
		req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
		req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
	}

	if wi.config.EvasionLevel >= 3 {
		req.Header.Set("DNT", "1")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Upgrade-Insecure-Requests", "1")
		req.Header.Set("Cache-Control", "max-age=0")
	}

	if wi.config.EvasionLevel >= 4 {
		randIP := fmt.Sprintf("%d.%d.%d.%d", rand.Intn(255), rand.Intn(255), rand.Intn(255), rand.Intn(255))
		req.Header.Set("X-Forwarded-For", randIP)
		req.Header.Set("X-Real-IP", randIP)
		req.Header.Set("CF-Connecting-IP", randIP)
	}

	if wi.config.EvasionLevel >= 5 {
		req.Header.Set("X-Originating-IP", fmt.Sprintf("%d.%d.%d.%d", rand.Intn(255), rand.Intn(255), rand.Intn(255), rand.Intn(255)))
		req.Header.Set("X-Remote-IP", fmt.Sprintf("%d.%d.%d.%d", rand.Intn(255), rand.Intn(255), rand.Intn(255), rand.Intn(255)))
		req.Header.Set("X-Remote-Addr", fmt.Sprintf("%d.%d.%d.%d", rand.Intn(255), rand.Intn(255), rand.Intn(255), rand.Intn(255)))
		req.Header.Set("X-Client-IP", fmt.Sprintf("%d.%d.%d.%d", rand.Intn(255), rand.Intn(255), rand.Intn(255), rand.Intn(255)))
	}

	if wi.config.EvasionLevel >= 6 {
		req.Header.Set("X-Request-ID", uuid.New().String())
		req.Header.Set("X-Correlation-ID", uuid.New().String())
	}
}

func (wi *WebInferno) saveResult(result InfernoResult) {
    if wi.config.OutputSuccess == "" {
        return
    }

    f, err := os.OpenFile(wi.config.OutputSuccess, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return
    }
    defer f.Close()

    var line string
    
    if wi.config.OutputFormat != "" {
        line = wi.config.OutputFormat
        for k, v := range result.Variables {
            placeholder := "{" + k + "}"
            line = strings.ReplaceAll(line, placeholder, v)
        }
        line = line + "\n"
    } else {
        varsStr := ""
        for k, v := range result.Variables {
            varsStr += fmt.Sprintf("%s=%s ", k, v)
        }
        line = fmt.Sprintf("%s\n", strings.TrimSpace(varsStr))
    }
    
    f.WriteString(line)
}

func (wi *WebInferno) saveToken(name, value string, vars map[string]string) {
	if wi.config.OutputTokens == "" {
		return
	}

	f, err := os.OpenFile(wi.config.OutputTokens, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	line := fmt.Sprintf("[%s] %s = %s | vars: %v\n",
		time.Now().Format("15:04:05"),
		name,
		value,
		vars,
	)
	f.WriteString(line)
}

func (wi *WebInferno) printHeader() {
	fmt.Printf("\n%s", strings.Repeat("=", 70))
	fmt.Printf("\n WEB INFERNO - Advanced HTTP Attack Engine v2.0")
	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
}

func (wi *WebInferno) printStats() {
	fmt.Printf("\n\n%s", strings.Repeat("=", 70))
	fmt.Printf("\n STATISTICS")
	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
	fmt.Printf("Total Requests:   %d\n", wi.stats.Load())
	fmt.Printf("Successful:       %d\n", wi.successCount.Load())
	fmt.Printf("Failed:           %d\n", wi.failCount.Load())
	fmt.Printf("Success Rate:     %.2f%%\n", float64(wi.successCount.Load())/float64(wi.stats.Load()+1)*100)
	fmt.Printf("Output File:      %s\n", wi.config.OutputSuccess)
	if len(wi.nodes) > 0 {
		fmt.Printf("Cluster Mode:     Active (%d nodes)\n", len(wi.nodes))
	}
	if wi.config.EvasionLevel > 0 {
		fmt.Printf("Evasion Level:    %d\n", wi.config.EvasionLevel)
	}
	fmt.Printf("%s\n", strings.Repeat("=", 70))
}

func (wi *WebInferno) GetResults() <-chan InfernoResult {
	return wi.results
}

func (wi *WebInferno) Stop() {
	wi.stopFlag.Store(true)
	if wi.wsConn != nil {
		wi.wsConn.Close()
	}
}

func randomUserAgent() string {
	agents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/119.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
	}
	return agents[rand.Intn(len(agents))]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
