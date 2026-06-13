package checker

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (c *Checker) checkCPanel(target, username, password string) CheckerResult {
	start := time.Now()

	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimSuffix(target, "/")

	host := target
	if idx := strings.Index(target, ":"); idx != -1 {
		host = target[:idx]
	}

	loginURL := "https://" + host + ":2083/login/?login_only=1"

	success := c.tryCPanelLogin(loginURL, username, password)

	return CheckerResult{
		Target:       target,
		Username:     username,
		Password:     password,
		Type:         "cpanel",
		Success:      success,
		ResponseTime: time.Since(start),
	}
}

func (c *Checker) tryCPanelLogin(loginURL, username, password string) bool {
	data := url.Values{}
	data.Set("user", username)
	data.Set("pass", password)

	req, err := http.NewRequest("POST", loginURL, strings.NewReader(data.Encode()))
	if err != nil {
		return false
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := c.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if strings.Contains(bodyStr, `"status":1`) && strings.Contains(bodyStr, "security_token") {
		return true
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err == nil {
		if status, ok := result["status"]; ok {
			if status == float64(1) {
				return true
			}
		}
	}

	return false
}
