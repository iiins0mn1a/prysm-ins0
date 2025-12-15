package helpers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/prysmaticlabs/prysm/v5/io/file"
)

const specLogRoot = "/home/ins0/Repos/Event-Driven-Testnet/shadow-ethereum/spec.log"
const specLogNodeEnv = "SPEC_LOG_NODE"

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

	nodeDir := resolveSpecLogNode()
	dir := filepath.Join(specLogRoot, nodeDir, module)
	if err := file.MkdirAll(dir); err != nil {
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
	defer func() {
		if err := f.Close(); err != nil {
			// best-effort close; ignore error to keep logging lightweight
		}
	}()

	if _, err := f.Write(payload); err != nil {
		return
	}
}

// resolveSpecLogNode picks node identifier for multi-node setups:
// 1) SPEC_LOG_NODE env var if set (caller's responsibility to ensure uniqueness);
// 2) hostname fallback; 3) "default" if hostname unavailable.
func resolveSpecLogNode() string {
	if v := os.Getenv(specLogNodeEnv); v != "" {
		return v
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "default"
}
