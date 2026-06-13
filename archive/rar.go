package archive

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nwaples/rardecode"
)

type RarCracker struct {
	filePath      string
	dictPath      string
	workers       int
	bufferSize    int
	foundPassword string
	foundFlag     int32
	testedCount   int64
	mu            sync.Mutex
}

type HeaderInfo struct {
	offset          int
	headerLen       int
	encryptedHeader []byte
	salt            []byte
}

type CrackResult struct {
	Success   bool
	Password  string
	TimeSpent time.Duration
	Tested    int64
	Error     string
}

func NRarCracker(rarFile, dictFile string, workers, bufferSize int) *RarCracker {
	if workers <= 0 {
		workers = runtime.NumCPU() * 2
	}
	if bufferSize <= 0 {
		bufferSize = 10000
	}
	return &RarCracker{
		filePath:   rarFile,
		dictPath:   dictFile,
		workers:    workers,
		bufferSize: bufferSize,
	}
}

func (rc *RarCracker) Crack() CrackResult {
	result := CrackResult{
		Success: false,
	}

	fmt.Printf("[RAR] Loading RAR file: %s\n", rc.filePath)
	rarData, err := os.ReadFile(rc.filePath)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to read RAR file: %v", err)
		return result
	}
	fmt.Printf("[RAR] File size: %.2f MB\n", float64(len(rarData))/1024/1024)

	fmt.Printf("[RAR] Analyzing RAR header...\n")
	headerInfo := analyzeRarHeader(rarData)
	if headerInfo.offset == 0 {
		result.Error = "Invalid RAR file or header not found"
		return result
	}
	fmt.Printf("[RAR] Header found at offset: %d\n", headerInfo.offset)

	passwords, err := readLines(rc.dictPath)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to read dictionary: %v", err)
		return result
	}
	fmt.Printf("[RAR] Loaded %d passwords\n", len(passwords))

	passwordsChan := make(chan string, rc.bufferSize)
	go func() {
		for _, pwd := range passwords {
			if atomic.LoadInt32(&rc.foundFlag) == 1 {
				break
			}
			passwordsChan <- pwd
		}
		close(passwordsChan)
	}()

	fmt.Printf("[RAR] Starting %d workers...\n", rc.workers)
	startTime := time.Now()

	var wg sync.WaitGroup
	for i := 0; i < rc.workers; i++ {
		wg.Add(1)
		go rc.worker(i, rarData, headerInfo, passwordsChan, &wg)
	}

	go rc.showProgress(&result, len(passwords))

	wg.Wait()
	result.TimeSpent = time.Since(startTime)
	result.Tested = atomic.LoadInt64(&rc.testedCount)

	if rc.foundPassword != "" {
		result.Success = true
		result.Password = rc.foundPassword
	}

	return result
}

func (rc *RarCracker) worker(id int, rarData []byte, headerInfo *HeaderInfo, passwordsChan <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	localBuffer := make([]byte, headerInfo.headerLen)

	for pwd := range passwordsChan {
		if atomic.LoadInt32(&rc.foundFlag) == 1 {
			return
		}

		atomic.AddInt64(&rc.testedCount, 1)

		if rc.checkPassword(rarData, headerInfo, pwd, localBuffer) {
			if atomic.CompareAndSwapInt32(&rc.foundFlag, 0, 1) {
				rc.mu.Lock()
				rc.foundPassword = pwd
				rc.mu.Unlock()
				fmt.Printf("\n\n[RAR] ✓ FOUND PASSWORD: %s\n\n", pwd)
			}
			return
		}
	}
}

func (rc *RarCracker) checkPassword(rarData []byte, headerInfo *HeaderInfo, password string, buffer []byte) bool {
	reader := bytes.NewReader(rarData)
	rd, err := rardecode.NewReader(reader, password)
	if err != nil {
		return false
	}

	_, err = rd.Next()
	return err == nil
}

func (rc *RarCracker) showProgress(result *CrackResult, total int) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		if atomic.LoadInt32(&rc.foundFlag) == 1 {
			return
		}
		tested := atomic.LoadInt64(&rc.testedCount)
		if total > 0 {
			percent := float64(tested) / float64(total) * 100
			fmt.Printf("\r[RAR] Progress: %.1f%% (%d/%d passwords)", percent, tested, total)
		}
	}
}

func analyzeRarHeader(data []byte) *HeaderInfo {
	info := &HeaderInfo{}

	for i := 0; i < len(data)-100; i++ {
		if data[i] == 0x73 && data[i+1] == 0x00 {
			info.offset = i
			if i+9 < len(data) {
				info.headerLen = int(data[i+7]) | int(data[i+8])<<8
			}
			if i+info.headerLen < len(data) && info.headerLen > 0 {
				info.encryptedHeader = data[i : i+info.headerLen]
			}
			break
		}
	}

	return info
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}
