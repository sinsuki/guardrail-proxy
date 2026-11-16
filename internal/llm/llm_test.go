package llm_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sinsuki/guardrail-proxy/internal/audit"
	"github.com/sinsuki/guardrail-proxy/internal/fakellm"
	"github.com/sinsuki/guardrail-proxy/internal/llm"
)

func TestLLMRedactsAndRestores(t *testing.T) {
	var got []byte
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read: %v", err)
			return
		}
		got = append([]byte(nil), body...)
		fakellm.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(body))))
	}))
	t.Cleanup(up.Close)
	proxy, err := llm.New(up.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	body := `{"messages":[{"role":"user","content":"email ada@example.com about card 4111111111111111"}],"amount_cents":50001}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/llm", strings.NewReader(body))
	proxy.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	fwd := string(got)
	if strings.Contains(fwd, "ada@example.com") || strings.Contains(fwd, "4111111111111111") {
		t.Fatalf("pii forwarded: %s", fwd)
	}
	if !strings.Contains(fwd, "[EMAIL_1]") || !strings.Contains(fwd, "[CARD_1]") {
		t.Fatalf("placeholders missing: %s", fwd)
	}
	if !strings.Contains(fwd, `"amount_cents":50001`) {
		t.Fatalf("number changed: %s", fwd)
	}
	out := rec.Body.String()
	if !strings.Contains(out, "ada@example.com") || !strings.Contains(out, "4111111111111111") {
		t.Fatalf("reply was not restored: %s", out)
	}
	if !strings.Contains(out, `"to":"ada@example.com"`) {
		t.Fatalf("tool call was not restored: %s", out)
	}
	if strings.Contains(out, "[EMAIL_1]") || strings.Contains(out, "[CARD_1]") {
		t.Fatalf("placeholder left in reply: %s", out)
	}
	if !strings.Contains(rec.Header().Get(llm.HeaderRedacted), "email=1") {
		t.Fatal(rec.Header().Get(llm.HeaderRedacted))
	}
}

func TestLLMPlainText(t *testing.T) {
	up := httptest.NewServer(fakellm.Handler())
	t.Cleanup(up.Close)
	proxy, err := llm.New(up.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/llm", strings.NewReader("ssn 123-45-6789"))
	proxy.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "123-45-6789") {
		t.Fatalf("%s", rec.Body.String())
	}
}

func TestLLMDoesNotFlagBadLuhn(t *testing.T) {
	var got string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"echo":"ok"}`))
	}))
	t.Cleanup(up.Close)
	proxy, err := llm.New(up.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/llm", strings.NewReader(`{"prompt":"order 4111111111111112"}`))
	proxy.Handler().ServeHTTP(rec, req)
	if !strings.Contains(got, "4111111111111112") {
		t.Fatalf("non-card was redacted: %s", got)
	}
	if rec.Header().Get(llm.HeaderRedacted) != "none" {
		t.Fatal(rec.Header().Get(llm.HeaderRedacted))
	}
}

func TestRedactionAuditOmitsValues(t *testing.T) {
	up := httptest.NewServer(fakellm.Handler())
	t.Cleanup(up.Close)
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
	logPath := filepath.Join(dir, "audit.jsonl")
	l, err := audit.Open(logPath, priv)
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := llm.New(up.URL, nil, llm.WithAudit(l))
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/llm", strings.NewReader(`{"prompt":"email ada@example.com"}`))
	proxy.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	n, err := audit.Verify(logPath, pubPath)
	if err != nil || n != 2 {
		t.Fatalf("verify n=%d err=%v", n, err)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "ada@example.com") || strings.Contains(string(raw), "[EMAIL_1]") {
		t.Fatalf("log leaked prompt data: %s", raw)
	}
	if !strings.Contains(string(raw), `"email":1`) {
		t.Fatalf("counts missing: %s", raw)
	}
}

func TestForwardsAuthorization(t *testing.T) {
	var got string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(up.Close)
	proxy, err := llm.New(up.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/llm", strings.NewReader(`{"prompt":"hello"}`))
	req.Header.Set("Authorization", "Bearer secret-token")
	proxy.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if got != "Bearer secret-token" {
		t.Fatalf("authorization %q", got)
	}
}

func TestNewRejectsBadURL(t *testing.T) {
	if _, err := llm.New("/relative", nil); err == nil {
		t.Fatal("accepted relative url")
	}
}
