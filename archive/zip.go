package archive

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alexmullins/zip"
)

type ZipCrackResult struct {
	Success   bool
	Password  string
	TimeSpent time.Duration
	Tested    int64
	Error     string
}

type ZipCracker struct {
	filePath      string
	dictPath      string
	workers       int
	bufferSize    int
	foundPassword string
	foundFlag     int32
	testedCount   int64
	mu            sync.Mutex
}

func NZipCracker(zipFile, dictFile string, workers, bufferSize int) *ZipCracker {
	if workers <= 0 {
		workers = runtime.NumCPU() * 2
	}
	if bufferSize <= 0 {
		bufferSize = 10000
	}
	return &ZipCracker{
		filePath:   zipFile,
		dictPath:   dictFile,
		workers:    workers,
		bufferSize: bufferSize,
	}
}

func (zc *ZipCracker) Crack() ZipCrackResult {
	result := ZipCrackResult{
		Success: false,
	}

	fmt.Printf("[ZIP] Loading ZIP file: %s\n", zc.filePath)
	zipData, err := os.ReadFile(zc.filePath)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to read ZIP file: %v", err)
		return result
	}
	fmt.Printf("[ZIP] File size: %.2f MB\n", float64(len(zipData))/1024/1024)

	passwords, err := readLines(zc.dictPath)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to read dictionary: %v", err)
		return result
	}
	fmt.Printf("[ZIP] Loaded %d passwords\n", len(passwords))

	if len(passwords) == 0 {
		result.Error = "No passwords in dictionary file"
		return result
	}

	passwordsChan := make(chan string, zc.bufferSize)
	go func() {
		for _, pwd := range passwords {
			if atomic.LoadInt32(&zc.foundFlag) == 1 {
				break
			}
			passwordsChan <- pwd
		}
		close(passwordsChan)
	}()

	fmt.Printf("[ZIP] Starting %d workers...\n", zc.workers)
	startTime := time.Now()

	var wg sync.WaitGroup
	for i := 0; i < zc.workers; i++ {
		wg.Add(1)
		go zc.worker(zipData, passwordsChan, &wg)
	}

	go zc.showProgress(&result, len(passwords))

	wg.Wait()
	result.TimeSpent = time.Since(startTime)
	result.Tested = atomic.LoadInt64(&zc.testedCount)

	if zc.foundPassword != "" {
		result.Success = true
		result.Password = zc.foundPassword
	}

	return result
}

func (zc *ZipCracker) worker(zipData []byte, passwordsChan <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	for pwd := range passwordsChan {
		if atomic.LoadInt32(&zc.foundFlag) == 1 {
			return
		}

		atomic.AddInt64(&zc.testedCount, 1)

		if zc.checkPassword(zipData, pwd) {
			if atomic.CompareAndSwapInt32(&zc.foundFlag, 0, 1) {
				zc.mu.Lock()
				zc.foundPassword = pwd
				zc.mu.Unlock()
				fmt.Printf("\n\n[ZIP] ✓ FOUND PASSWORD: %s\n\n", pwd)
			}
			return
		}
	}
}

func (zc *ZipCracker) checkPassword(zipData []byte, password string) bool {
	reader := bytes.NewReader(zipData)
	zr, err := zip.NewReader(reader, int64(len(zipData)))
	if err != nil {
		return false
	}

	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		f.SetPassword(password)
		rc, err := f.Open()
		if err != nil {
			return false
		}
		defer rc.Close()
		_, err = io.Copy(io.Discard, rc)
		if err == nil {
			return true
		}
	}
	return false
}

func (zc *ZipCracker) showProgress(result *ZipCrackResult, total int) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		if atomic.LoadInt32(&zc.foundFlag) == 1 {
			return
		}
		tested := atomic.LoadInt64(&zc.testedCount)
		if total > 0 {
			percent := float64(tested) / float64(total) * 100
			fmt.Printf("\r[ZIP] Progress: %.1f%% (%d/%d passwords)", percent, tested, total)
		}
	}
}
