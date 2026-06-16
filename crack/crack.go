package crack

import (
	"fmt"
	"crypto/des"
	"time"
	"net"
	"context"
	"encoding/binary"
	"strings"
)

type CrackResult struct {
	Host     string
	Port     string
	User     string
	Password string
	Success  bool
	Protocol string
}

const (
	telnetIAC   = 255 
	telnetWILL  = 251
	telnetWONT  = 252
	telnetDO    = 253
	telnetDONT  = 254
	vncAuthVNC      = 2
)

func runSMB(host, port string, user, pass string, timeout int) bool {
	if port == "" {
		port = "445"
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return false
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))

	request := BuildSMB2NegotiateRequest()
	if _, err := conn.Write(request); err == nil {
		response := make([]byte, 1024)
		n, err := conn.Read(response)
		if err == nil && n > 0 {
			if n > 4 && response[4] == 0xFE {
				return attemptSMBAuth(conn, user, pass)
			}
		}
	}

	conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	request = BuildSMBNegotiateRequest()
	if _, err := conn.Write(request); err != nil {
		return false
	}

	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return false
	}

	if n > 4 && response[4] == 0xFF {
		return attemptSMBAuth(conn, user, pass)
	}

	return false
}

func attemptSMBAuth(conn net.Conn, user, pass string) bool {

	setupRequest := buildSMBSessionSetup(user, pass)
	if _, err := conn.Write(setupRequest); err != nil {
		return false
	}

	response := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(response)
	if err != nil {
		return false
	}

	if n > 8 {
		status := binary.LittleEndian.Uint32(response[8:12])
		if status == 0x00000000 {
			return true
		}
	}

	return false
}

func SMBCrack(host, port string, users, passes []string, timeout int) <-chan CrackResult {
	results := make(chan CrackResult, 100)

	go func() {
		defer close(results)

		for _, user := range users {
			for _, pass := range passes {
				success := runSMB(host, port, user, pass, timeout)
				results <- CrackResult{
					Host:     host,
					Port:     port,
					User:     user,
					Password: pass,
					Success:  success,
					Protocol: "SMB",
				}
			}
		}
	}()

	return results
}

func handleTelnetNegotiation(conn net.Conn) error {
	buf := make([]byte, 3)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	for {
		_, err := conn.Read(buf)
		if err != nil {
			break
		}

		if buf[0] == telnetIAC {
			switch buf[1] {
			case telnetWILL, telnetWONT:

				response := []byte{telnetIAC, telnetDONT, buf[2]}
				conn.Write(response)
			case telnetDO, telnetDONT:

				response := []byte{telnetIAC, telnetWONT, buf[2]}
				conn.Write(response)
			}
		}
	}
	return nil
}

type VNCHandshake struct {
	ProtocolVersion string
	SecurityTypes   []uint32
	Challenge       []byte
}

func runVNC(host, port string, password string, timeout int) bool {
    if port == "" {
        port = "5900"
    }

    ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
    defer cancel()

    var dialer net.Dialer
    conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
    if err != nil {
        return false
    }
    defer conn.Close()

    conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))

    version := make([]byte, 12)
    _, err = conn.Read(version)
    if err != nil {
        return false
    }

    ourVersion := []byte("RFB 003.008\n")
    if _, err := conn.Write(ourVersion); err != nil {
        return false
    }

    secTypeCount := make([]byte, 1)
    _, err = conn.Read(secTypeCount)
    if err != nil {
        return false
    }

    secTypes := make([]byte, secTypeCount[0])
    _, err = conn.Read(secTypes)
    if err != nil {
        return false
    }

    vncAuthSupported := false
    for _, t := range secTypes {
        if t == byte(vncAuthVNC) {
            vncAuthSupported = true
            break
        }
    }

    if !vncAuthSupported {
        return false
    }

    _, err = conn.Write([]byte{byte(vncAuthVNC)})
    if err != nil {
        return false
    }

    challenge := make([]byte, 16)
    _, err = conn.Read(challenge)
    if err != nil {
        return false
    }

    response, err := encryptVNCPasswordFull(password, challenge)
    if err != nil {
        return false
    }

    _, err = conn.Write(response)
    if err != nil {
        return false
    }

    result := make([]byte, 4)
    _, err = conn.Read(result)
    if err != nil {
        return false
    }

    return binary.BigEndian.Uint32(result) == 0
}

func encryptVNCPasswordFull(password string, challenge []byte) ([]byte, error) {
    key := make([]byte, 8)
    copy(key, []byte(password))
    for i := len(password); i < 8; i++ {
        key[i] = 0
    }

    for i := 0; i < 8; i++ {
        key[i] = (key[i] & 0xFE) | ((key[i] >> 7) & 1)
    }
    
    block, err := des.NewCipher(key)
    if err != nil {
        return nil, fmt.Errorf("failed to create DES cipher: %v", err)
    }
    
    response := make([]byte, 16)
    for i := 0; i < 16; i += 8 {
        block.Encrypt(response[i:i+8], challenge[i:i+8])
    }
    
    return response, nil
}

func runTelnetEnhanced(host, port string, user, pass string, timeout int) bool {
    if port == "" {
        port = "23"
    }

    ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
    defer cancel()

    var dialer net.Dialer
    conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
    if err != nil {
        return false
    }
    defer conn.Close()

    conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))

    handleTelnetNegotiation(conn)
    buf := make([]byte, 4096)
    conn.Read(buf)

    _, err = conn.Write([]byte(user + "\r\n"))
    if err != nil {
        return false
    }

    passwordPrompt := make([]byte, 1024)
    conn.SetReadDeadline(time.Now().Add(5 * time.Second))
    n, err := conn.Read(passwordPrompt)
    if err != nil {
        return false
    }

    prompt := strings.ToLower(string(passwordPrompt[:n]))
    if !strings.Contains(prompt, "password") && !strings.Contains(prompt, "passwd") {
        return false
    }

    _, err = conn.Write([]byte(pass + "\r\n"))
    if err != nil {
        return false
    }

    conn.SetReadDeadline(time.Now().Add(5 * time.Second))
    response := make([]byte, 8192)
    n, err = conn.Read(response)
    if err != nil {
        return false
    }

    respStr := strings.ToLower(string(response[:n]))

    failurePatterns := []string{
        "login failed", "login incorrect", "authentication failed",
        "access denied", "invalid password", "invalid username",
        "login invalid", "password error", "denied", "failed",
    }
    for _, pattern := range failurePatterns {
        if strings.Contains(respStr, pattern) {
            return false
        }
    }

    promptPatterns := []string{"$", "#", ">", "%", "]", "~", "welcome", "connected"}
    for _, pattern := range promptPatterns {
        if strings.Contains(respStr, pattern) {
            return true
        }
    }

    _, err = conn.Write([]byte("echo OK\r\n"))
    if err != nil {
        return false
    }

    time.Sleep(500 * time.Millisecond)
    conn.SetReadDeadline(time.Now().Add(2 * time.Second))
    testResp := make([]byte, 256)
    n, err = conn.Read(testResp)
    if err == nil && strings.Contains(string(testResp[:n]), "OK") {
        return true
    }

    return false
}

func TelnetCrack(host, port string, users, passes []string, timeout int) <-chan CrackResult {
    results := make(chan CrackResult, 100)

    go func() {
        defer close(results)
        for _, user := range users {
            for _, pass := range passes {
                success := runTelnetEnhanced(host, port, user, pass, timeout)
                results <- CrackResult{
                    Host:     host,
                    Port:     port,
                    User:     user,
                    Password: pass,
                    Success:  success,
                    Protocol: "Telnet",
                }
            }
        }
    }()
    return results
}

func VNCCrack(host, port string, passes []string, timeout int) <-chan CrackResult {
	results := make(chan CrackResult, 100)

	go func() {
		defer close(results)

		for _, pass := range passes {
			success := runVNC(host, port, pass, timeout)
			results <- CrackResult{
				Host:     host,
				Port:     port,
				User:     "", 
				Password: pass,
				Success:  success,
				Protocol: "VNC",
			}
		}
	}()

	return results
}


// -------------------------- BUILDS --------------------------

func BuildNTLMNegotiateMessage() []byte {
    msg := make([]byte, 40)
    copy(msg[0:8], []byte("NTLMSSP\x00"))
    binary.LittleEndian.PutUint32(msg[8:12], 1)
    binary.LittleEndian.PutUint32(msg[12:16], 0x00000207)
    return msg
}

func BuildNTLMAuthenticateMessage(user, pass, domain string, challenge []byte) []byte {
    msg := make([]byte, 200)
    copy(msg[0:8], []byte("NTLMSSP\x00"))
    binary.LittleEndian.PutUint32(msg[8:12], 3)
    
    lmRespOffset := 40
    copy(msg[lmRespOffset:lmRespOffset+24], make([]byte, 24))
    binary.LittleEndian.PutUint32(msg[12:16], uint32(lmRespOffset))
    binary.LittleEndian.PutUint32(msg[16:20], 24)
    
    ntResp := hashNTLMv2(pass, challenge)
    ntRespOffset := lmRespOffset + 24
    copy(msg[ntRespOffset:ntRespOffset+len(ntResp)], ntResp)
    binary.LittleEndian.PutUint32(msg[20:24], uint32(ntRespOffset))
    binary.LittleEndian.PutUint32(msg[24:28], uint32(len(ntResp)))
    
    userOffset := ntRespOffset + len(ntResp)
    userBytes := []byte(user)
    copy(msg[userOffset:userOffset+len(userBytes)], userBytes)
    binary.LittleEndian.PutUint32(msg[28:32], uint32(userOffset))
    binary.LittleEndian.PutUint32(msg[32:36], uint32(len(userBytes)))
    
    return msg[:userOffset+len(userBytes)+4]
}

func hashNTLMv2(password string, challenge []byte) []byte {
    hash := make([]byte, 16)
    for i := 0; i < 16 && i < len(challenge); i++ {
        hash[i] = challenge[i] ^ byte(password[i%len(password)])
    }
    return hash
}

func BuildSMBNegotiateRequest() []byte {
	header := []byte{
		0x00, 0x00, 0x00, 0x85,
		0xFF, 0x53, 0x4D, 0x42, 
		0x72, 
		0x00, 0x00, 0x00, 0x00, 
		0x18,
		0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00,
	}

	params := []byte{
		0x00,
		0x00, 0x00,
	}

	dialects := []byte{
		0x02, 0x4E, 0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00,
	}

	request := append(header, params...)
	request = append(request, dialects...)
	return request
}

func BuildSMB2NegotiateRequest() []byte {

	request := []byte{
		0x00, 0x00, 0x00, 0x40,
		0xFE, 0x53, 0x4D, 0x42, 
		0x40, 0x00, 
		0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 
		0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x24, 0x00,
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 
		0x02, 0x10, 
		0x03, 0x00,
		0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	return request
}

func buildSMBSessionSetup(user, pass string) []byte {
	request := []byte{
		0x00, 0x00, 0x00, 0x4A, 
		0xFF, 0x53, 0x4D, 0x42, 
		0x73,
		0x00, 0x00, 0x00, 0x00, 
		0x18,
		0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00,
		0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00,
		0x0C, 
		0xFF, 0xFF, 0x00, 0x00,
		0x00, 0x00, 
		0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00,
	}
	return request
}
