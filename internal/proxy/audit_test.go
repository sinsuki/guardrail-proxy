package proxy_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sinsuki/guardrail-proxy/internal/audit"
	"github.com/sinsuki/guardrail-proxy/internal/proxy"
)

func TestToolCallIsAuditedWithoutTheBody(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(up.Close)
	l, path, pub := openAudit(t)
	defer l.Close()
	handler, err := proxy.New(loadPolicy(t), up.URL, nil, proxy.WithAudit(l))
	if err != nil {
		t.Fatal(err)
	}
	body := `{"tool":"transfer","arguments":{"from_account":"acct_1","to_account":"acct_2","amount_cents":100,"currency":"USD"}}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/tool-calls", strings.NewReader(body))
	handler.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	n, err := audit.Verify(path, pub)
	if err != nil || n != 4 {
		t.Fatalf("verify n=%d err=%v", n, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, "acct_1") || strings.Contains(text, "amount_cents") {
		t.Fatalf("log stored the call body: %s", text)
	}
	for _, kind := range []string{audit.KindToolCall, audit.KindSchema, audit.KindDecision, audit.KindForward} {
		if !strings.Contains(text, `"kind":"`+kind+`"`) {
			t.Fatalf("missing %s in %s", kind, text)
		}
	}
}

func TestAuditFailureDoesNotForward(t *testing.T) {
	var hits int
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
	}))
	t.Cleanup(up.Close)
	handler, err := proxy.New(loadPolicy(t), up.URL, nil, proxy.WithAudit(failingAudit{}))
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/tool-calls", strings.NewReader(transfer("100")))
	handler.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "audit log failed") {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if hits != 0 {
		t.Fatal("forwarded")
	}
}

type failingAudit struct{}

func (failingAudit) Append(string, any) error { return errAudit }

type auditError string

func (e auditError) Error() string { return string(e) }

var errAudit = auditError("disk full")

func openAudit(t *testing.T) (*audit.Log, string, string) {
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
