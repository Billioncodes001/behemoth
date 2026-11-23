package evidence

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
)

// RunLog is a tamper-evident, append-only JSONL record of one agent run's
// activity stream. Every entry carries:
//
//   - the SHA-256 of its full detail blob (so a summarized/lazy-loaded activity
//     row can still be tied to a byte-exact body);
//   - the previous entry's hash (a Merkle-ish chain: altering, reordering or
//     dropping an entry breaks every later hash).
//
// The head hash of the finished log is small enough to store next to the run (in
// the terminal activity's metadata) and lets a reviewer prove the log they hold is
// the log the engine produced. VerifyRunLog replays the chain.

// LogRecord is one JSONL line.
type LogRecord struct {
	Seq          int    `json:"seq"`
	TS           string `json:"ts"`
	Kind         string `json:"kind,omitempty"`
	Tool         string `json:"tool,omitempty"`
	ToolUseID    string `json:"tool_use_id,omitempty"`
	IsError      bool   `json:"is_error,omitempty"`
	Summary      string `json:"summary,omitempty"`
	DetailSHA256 string `json:"detail_sha256,omitempty"`
	DetailBytes  int    `json:"detail_bytes,omitempty"`
	PrevHash     string `json:"prev_hash,omitempty"`
	Hash         string `json:"hash"`
}

// RunLog appends records to one JSONL file. Safe for concurrent use.
type RunLog struct {
	mu   sync.Mutex
	f    *os.File
	path string
	seq  int
	prev string
}

// OpenRunLog opens (creating parents) the JSONL file at path for appending.
// Existing content is continued: seq and the chain head are recovered so a
// resumed run keeps one unbroken chain.
func OpenRunLog(path string) (*RunLog, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	l := &RunLog{path: path}
	if existing, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(existing)
		sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var rec LogRecord
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				break
			}
			l.seq = rec.Seq + 1
			l.prev = rec.Hash
		}
		_ = existing.Close()
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	l.f = f
	return l, nil
}

// hashRecord computes the chain hash of a record (excluding its Hash field).
func hashRecord(rec LogRecord) string {
	rec.Hash = ""
	b, _ := json.Marshal(rec) // stable field order: struct order
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Append writes one activity as a chained record and returns its hash.
func (l *RunLog) Append(a db.Activity) (string, error) {
	if l == nil || l.f == nil {
		return "", errors.New("run log is closed")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	detailSum := sha256.Sum256([]byte(a.Detail))
	rec := LogRecord{
		Seq:          l.seq,
		TS:           time.Now().UTC().Format(time.RFC3339Nano),
		Kind:         a.Kind,
		Tool:         a.Tool,
		ToolUseID:    a.ToolUseID,
		IsError:      a.IsError,
		Summary:      a.Summary,
		DetailSHA256: hex.EncodeToString(detailSum[:]),
		DetailBytes:  len(a.Detail),
		PrevHash:     l.prev,
	}
	if a.CreatedAt.IsZero() {
		rec.TS = time.Now().UTC().Format(time.RFC3339Nano)
	} else {
		rec.TS = a.CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	rec.Hash = hashRecord(rec)
	line, err := json.Marshal(rec)
	if err != nil {
		return "", err
	}
	if _, err := fmt.Fprintf(l.f, "%s\n", line); err != nil {
		return "", err
	}
	l.seq++
	l.prev = rec.Hash
	return rec.Hash, nil
}

// HeadHash is the chain head (last entry's hash; empty for an empty log).
func (l *RunLog) HeadHash() string {
	if l == nil {
		return ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.prev
}

// Seq is the next sequence number.
func (l *RunLog) Seq() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.seq
}

// Path returns the file path.
func (l *RunLog) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

// Close closes the underlying file.
func (l *RunLog) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	err := l.f.Close()
	l.f = nil
	return err
}

// LogVerification is the outcome of replaying a run log's hash chain.
type LogVerification struct {
	Path     string   `json:"path"`
	Records  int      `json:"records"`
	HeadHash string   `json:"head_hash,omitempty"`
	Valid    bool     `json:"valid"`
	Problems []string `json:"problems,omitempty"`
}

// VerifyRunLog replays the JSONL chain at path and reports whether every entry's
// hash and link is intact. A non-empty Problems list names the first failures
// (sequence gaps, broken prev-hash links, mismatched recomputed hashes).
func VerifyRunLog(path string) (*LogVerification, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck

	v := &LogVerification{Path: path, Valid: true}
	prev := ""
	expectedSeq := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec LogRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			v.Valid = false
			v.Problems = append(v.Problems, fmt.Sprintf("line %d: invalid JSON: %v", v.Records+1, err))
			break
		}
		if rec.Seq != expectedSeq {
			v.Valid = false
			v.Problems = append(v.Problems, fmt.Sprintf("record %d: sequence is %d, expected %d", v.Records+1, rec.Seq, expectedSeq))
		}
		if rec.PrevHash != prev {
			v.Valid = false
			v.Problems = append(v.Problems, fmt.Sprintf("record %d: prev_hash does not match the previous record", v.Records+1))
		}
		if want := hashRecord(rec); want != rec.Hash {
			v.Valid = false
			v.Problems = append(v.Problems, fmt.Sprintf("record %d: hash mismatch (content was modified)", v.Records+1))
		}
		prev = rec.Hash
		expectedSeq = rec.Seq + 1
		v.Records++
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	v.HeadHash = prev
	return v, nil
}

// VerifyDetail checks one record's detail blob against its stored digest. Callers
// pair it with the activity row's Detail (lazy-loaded) to prove the row still
// matches the log entry.
func (r LogRecord) VerifyDetail(detail string) bool {
	sum := sha256.Sum256([]byte(detail))
	return hex.EncodeToString(sum[:]) == r.DetailSHA256 && len(detail) == r.DetailBytes
}

// ParseRunLog decodes a JSONL log into records (used by the CLI and tests).
func ParseRunLog(r *bufio.Scanner) ([]LogRecord, error) {
	out := []LogRecord{}
	for r.Scan() {
		line := strings.TrimSpace(r.Text())
		if line == "" {
			continue
		}
		var rec LogRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return out, err
		}
		out = append(out, rec)
	}
	return out, r.Err()
}
