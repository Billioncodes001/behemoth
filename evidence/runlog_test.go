package evidence

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestRunLogChainAndVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence", "run.jsonl")
	log, err := OpenRunLog(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	activities := []db.Activity{
		{Kind: "tool_use", Tool: "Bash", Summary: "curl", Detail: "curl -s http://example.test"},
		{Kind: "tool_result", Tool: "Bash", Summary: "200 OK", Detail: "HTTP/1.1 200 OK\n\nhello"},
		{Kind: "result", Summary: "done", Detail: "done"},
	}
	for _, a := range activities {
		if _, err := log.Append(a); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	head := log.HeadHash()
	if len(head) != 64 {
		t.Fatalf("head hash = %q; want a sha256 hex digest", head)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	v, err := VerifyRunLog(path)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !v.Valid || v.Records != 3 || v.HeadHash != head {
		t.Fatalf("verification = %+v; want valid 3 records head %s", v, head)
	}

	// Tamper with one record's summary: the hash chain must break.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	tampered := strings.Replace(string(raw), `"summary":"200 OK"`, `"summary":"201 OK"`, 1)
	if tampered == string(raw) {
		t.Fatal("test did not modify the log")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	v, err = VerifyRunLog(path)
	if err != nil {
		t.Fatalf("verify tampered: %v", err)
	}
	if v.Valid || len(v.Problems) == 0 {
		t.Fatalf("tampered log verified clean: %+v", v)
	}
}

// Reopening a log continues one unbroken chain (resumed runs).
func TestRunLogContinuesChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.jsonl")
	first, err := OpenRunLog(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := first.Append(db.Activity{Kind: "tool_use", Tool: "Bash"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	head1 := first.HeadHash()
	_ = first.Close()

	second, err := OpenRunLog(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if second.HeadHash() != head1 || second.Seq() != 1 {
		t.Fatalf("reopened chain = head %s seq %d; want %s / 1", second.HeadHash(), second.Seq(), head1)
	}
	if _, err := second.Append(db.Activity{Kind: "result", Summary: "done"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	_ = second.Close()

	v, err := VerifyRunLog(path)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !v.Valid || v.Records != 2 {
		t.Fatalf("verification = %+v; want valid 2 records", v)
	}
}

// Detail digests bind a record to its exact blob.
func TestLogRecordVerifyDetail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.jsonl")
	log, err := OpenRunLog(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	detail := "exact body bytes"
	if _, err := log.Append(db.Activity{Kind: "tool_result", Detail: detail}); err != nil {
		t.Fatalf("append: %v", err)
	}
	_ = log.Close()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open file: %v", err)
	}
	defer f.Close() //nolint:errcheck
	sc := bufio.NewScanner(f)
	records, err := ParseRunLog(sc)
	if err != nil || len(records) != 1 {
		t.Fatalf("parse = %v, %v", records, err)
	}
	if !records[0].VerifyDetail(detail) {
		t.Fatal("verify detail failed for the exact blob")
	}
	if records[0].VerifyDetail(detail + "!") {
		t.Fatal("verify detail accepted a modified blob")
	}
}
