package checker

import (
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (c *Checker) checkWordPress(target, username, password string) CheckerResult {
	start := time.Now()

	success := c.tryWordPressLogin(target, username, password)

	return CheckerResult{
		Target:       target,
		Username:     username,
		Password:     password,
		Type:         "wordpress",
		Success:      success,
		ResponseTime: time.Since(start),
	}
}

func (c *Checker) tryWordPressLogin(loginURL, username, password string) bool {
	data := url.Values{}
	data.Set("log", username)
	data.Set("pwd", password)
	data.Set("wp-submit", "Log In")
	data.Set("testcookie", "1")

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

	for _, cookie := range resp.Cookies() {
		if strings.Contains(cookie.Name, "wordpress_logged_in") {
			return true
		}
	}

	if resp.StatusCode == 302 {
		location := resp.Header.Get("Location")
		if strings.Contains(location, "wp-admin") {
			return true
		}
	}

	return false
}
