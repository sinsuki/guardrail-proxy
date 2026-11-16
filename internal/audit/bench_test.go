package audit_test

import (
	"path/filepath"
	"testing"

	"github.com/sinsuki/guardrail-proxy/internal/audit"
)

func BenchmarkAppend(b *testing.B) {
	dir := b.TempDir()
	privPath := filepath.Join(dir, "audit.key")
	pubPath := filepath.Join(dir, "audit.pub")
	if err := audit.GenerateKey(privPath, pubPath); err != nil {
		b.Fatal(err)
	}
	priv, err := audit.LoadPrivate(privPath)
	if err != nil {
		b.Fatal(err)
	}
	l, err := audit.Open(filepath.Join(dir, "audit.jsonl"), priv)
	if err != nil {
		b.Fatal(err)
	}
	defer l.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := l.Append(audit.KindDecision, map[string]any{
			"tool": "transfer", "decision": "allow", "rule_id": "", "reason": "allowed",
		}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify10000(b *testing.B) {
	dir := b.TempDir()
	privPath := filepath.Join(dir, "audit.key")
	pubPath := filepath.Join(dir, "audit.pub")
	if err := audit.GenerateKey(privPath, pubPath); err != nil {
		b.Fatal(err)
	}
	priv, err := audit.LoadPrivate(privPath)
	if err != nil {
		b.Fatal(err)
	}
	path := filepath.Join(dir, "audit.jsonl")
	l, err := audit.Open(path, priv)
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < 10000; i++ {
		if err := l.Append(audit.KindForward, map[string]any{"target": "upstream", "status": 200, "bytes": i}); err != nil {
			b.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		b.Fatal(err)
	}
	if _, err := audit.Verify(path, pubPath); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		n, err := audit.Verify(path, pubPath)
		if err != nil || n != 10000 {
			b.Fatalf("n=%d err=%v", n, err)
		}
	}
}
