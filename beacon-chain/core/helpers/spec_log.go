package helpers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const specLogRoot = "/home/ins0/Repos/Event-Driven-Testnet/shadow-ethereum/spec.log"

type specLogEntry struct {
	Call   string `json:"call"`
	Module string `json:"module"`
	TS     int64  `json:"ts_unix_nano"`
}

var specLogLocks sync.Map // map[string]*sync.Mutex keyed by log file path

func getSpecLogLock(path string) *sync.Mutex {
	if val, ok := specLogLocks.Load(path); ok {
		return val.(*sync.Mutex)
	}
	mu := &sync.Mutex{}
	actual, _ := specLogLocks.LoadOrStore(path, mu)
	return actual.(*sync.Mutex)
}

// LogSpecCall appends a NDJSON line with call name and timestamp into
// shadow-ethereum/spec.log/<module>/<call>.log. Best-effort: silently
// returns on errors.
func LogSpecCall(module, call string) {
	if module == "" || call == "" {
		return
	}

	dir := filepath.Join(specLogRoot, module)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	logPath := filepath.Join(dir, call+".log")

	entry := specLogEntry{
		Call:   call,
		Module: module,
		TS:     time.Now().UnixNano(),
	}
	payload, err := json.Marshal(entry)
	if err != nil {
		return
	}
	payload = append(payload, '\n')

	mu := getSpecLogLock(logPath)
	mu.Lock()
	defer mu.Unlock()

	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()

	_, _ = f.Write(payload)
}
