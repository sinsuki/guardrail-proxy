package audit_test

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sinsuki/guardrail-proxy/internal/audit"
)

func newLog(t *testing.T) (*audit.Log, string, string) {
	t.Helper()
	dir := t.TempDir()
	privPath := filepath.Join(dir, "audit.key")
	pubPath := filepath.Join(dir, "audit.pub")
	if err := audit.GenerateKey(privPath, pubPath); err != nil {
		t.Fatal(err)
	}
	priv, err := audit.LoadPrivate(privPath)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "audit.jsonl")
	l, err := audit.Open(path, priv)
	if err != nil {
		t.Fatal(err)
	}
	return l, path, pubPath
}

func TestAppendAndVerify(t *testing.T) {
	l, path, pub := newLog(t)
	if err := l.Append(audit.KindDecision, map[string]string{"decision": "allow", "reason": "allowed"}); err != nil {
		t.Fatal(err)
	}
	if err := l.Append(audit.KindForward, map[string]any{"target": "upstream", "status": 200, "bytes": 12}); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	n, err := audit.Verify(path, pub)
	if err != nil || n != 2 {
		t.Fatalf("verify n=%d err=%v", n, err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"prev":"`+audit.Genesis+`"`) {
		t.Fatal("first entry is not chained to the genesis hash")
	}
}

func TestResumeAfterRestart(t *testing.T) {
	l, path, pub := newLog(t)
	priv, err := audit.LoadPrivate(filepath.Join(filepath.Dir(path), "audit.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Append("note", map[string]int{"n": 1}); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l2, err := audit.Open(path, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := l2.Append("note", map[string]int{"n": 2}); err != nil {
		t.Fatal(err)
	}
	if err := l2.Close(); err != nil {
		t.Fatal(err)
	}
	n, err := audit.Verify(path, pub)
	if err != nil || n != 2 {
		t.Fatalf("verify n=%d err=%v", n, err)
	}
}

func TestConcurrentAppends(t *testing.T) {
	l, path, pub := newLog(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if err := l.Append("note", map[string]int{"i": i, "j": j}); err != nil {
					t.Errorf("append: %v", err)
				}
			}
		}(i)
	}
	wg.Wait()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	n, err := audit.Verify(path, pub)
	if err != nil || n != 80 {
		t.Fatalf("verify n=%d err=%v", n, err)
	}
}

func TestTwoProcessesShareTheChain(t *testing.T) {
	l, path, pub := newLog(t)
	priv, err := audit.LoadPrivate(filepath.Join(filepath.Dir(path), "audit.key"))
	if err != nil {
		t.Fatal(err)
	}
	other, err := audit.Open(path, priv)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 15; i++ {
			if err := l.Append("a", map[string]int{"i": i}); err != nil {
				t.Errorf("a: %v", err)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 15; i++ {
			if err := other.Append("b", map[string]int{"i": i}); err != nil {
				t.Errorf("b: %v", err)
			}
		}
	}()
	wg.Wait()
	l.Close()
	other.Close()
	n, err := audit.Verify(path, pub)
	if err != nil || n != 30 {
		t.Fatalf("verify n=%d err=%v", n, err)
	}
}

func TestRedactionEventOmitsValues(t *testing.T) {
	l, path, _ := newLog(t)
	secret := "ada@example.com"
	if err := l.Append(audit.KindRedaction, map[string]int{"EMAIL": 1, "CARD": 1}); err != nil {
		t.Fatal(err)
	}
	l.Close()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), secret) {
		t.Fatal("audit log contains raw PII")
	}
	if !strings.Contains(string(body), `"EMAIL":1`) && !strings.Contains(string(body), `"EMAIL": 1`) {
		t.Fatalf("counts missing: %s", body)
	}
}

func TestTamper(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, path string)
		want   string
	}{
		{name: "edit", mutate: editPayload, want: "bad signature"},
		{name: "delete", mutate: deleteMiddle, want: "sequence"},
		{name: "reorder", mutate: reorder, want: "sequence"},
		{name: "insert", mutate: insertDuplicate, want: "sequence"},
		{name: "truncate", mutate: truncateLast, want: "log truncated"},
		{name: "bad signature", mutate: flipSignature, want: "bad signature"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l, path, pub := newLog(t)
			for i := 0; i < 5; i++ {
				if err := l.Append("note", map[string]int{"n": i}); err != nil {
					t.Fatal(err)
				}
			}
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}
			tc.mutate(t, path)
			_, err := audit.Verify(path, pub)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestWrongKey(t *testing.T) {
	l, path, _ := newLog(t)
	if err := l.Append("note", map[string]int{"n": 1}); err != nil {
		t.Fatal(err)
	}
	l.Close()
	dir := t.TempDir()
	priv := filepath.Join(dir, "other.key")
	pub := filepath.Join(dir, "other.pub")
	if err := audit.GenerateKey(priv, pub); err != nil {
		t.Fatal(err)
	}
	_, err := audit.Verify(path, pub)
	if err == nil || !strings.Contains(err.Error(), "bad signature") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "entry 1") {
		t.Fatalf("err = %v", err)
	}
}

func linesOf(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.TrimRight(string(b), "\n")
	return strings.Split(text, "\n")
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

func editPayload(t *testing.T, path string) {
	lines := linesOf(t, path)
	lines[1] = strings.Replace(lines[1], `"n":1`, `"n":9`, 1)
	writeLines(t, path, lines)
}

func deleteMiddle(t *testing.T, path string) {
	lines := linesOf(t, path)
	lines = append(lines[:2], lines[3:]...)
	writeLines(t, path, lines)
}

func reorder(t *testing.T, path string) {
	lines := linesOf(t, path)
	lines[1], lines[2] = lines[2], lines[1]
	writeLines(t, path, lines)
}

func insertDuplicate(t *testing.T, path string) {
	lines := linesOf(t, path)
	lines = append(lines[:2], append([]string{lines[1]}, lines[2:]...)...)
	writeLines(t, path, lines)
}

func truncateLast(t *testing.T, path string) {
	lines := linesOf(t, path)
	writeLines(t, path, lines[:len(lines)-1])
}

func flipSignature(t *testing.T, path string) {
	lines := linesOf(t, path)
	const marker = `,"sig":"`
	i := strings.LastIndex(lines[2], marker)
	if i < 0 {
		t.Fatal("no sig")
	}
	b := []byte(lines[2])
	b[i+len(marker)] ^= 1
	// Keep the character inside the base64 alphabet when the flip leaves it.
	if b[i+len(marker)] == 'A' {
		b[i+len(marker)] = 'B'
	}
	lines[2] = string(b)
	writeLines(t, path, lines)
}
