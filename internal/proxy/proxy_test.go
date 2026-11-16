package proxy_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sinsuki/guardrail-proxy/internal/config"
	"github.com/sinsuki/guardrail-proxy/internal/fakeupstream"
	"github.com/sinsuki/guardrail-proxy/internal/proxy"
	"github.com/sinsuki/guardrail-proxy/internal/rules"
	"github.com/sinsuki/guardrail-proxy/internal/schema"
)

func policyPath(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "policy.json")
}

func loadPolicy(t testing.TB) config.Policy {
	t.Helper()
	policy, err := config.Load(policyPath(t))
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func transfer(amount string) string {
	return `{"tool":"transfer","arguments":{"from_account":"acct_1","to_account":"acct_2","amount_cents":` + amount + `,"currency":"USD"}}`
}

type captured struct {
	hits   atomic.Int32
	mu     sync.Mutex
	body   string
	method string
	ct     string
	path   string
}

func (c *captured) snapshot() (string, string, string, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.body, c.method, c.ct, c.path
}

func TestProxyDecisions(t *testing.T) {
	var saw captured
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("upstream read: %v", err)
			return
		}
		saw.mu.Lock()
		saw.body = string(b)
		saw.method = r.Method
		saw.ct = r.Header.Get("Content-Type")
		saw.path = r.URL.Path
		saw.mu.Unlock()
		saw.hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(up.Close)

	handler, err := proxy.New(loadPolicy(t), up.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := handler.Handler()

	exact := `{"tool":"transfer","arguments":{"from_account":"acct_1","to_account":"acct_2","amount_cents":50000,"currency":"USD","memo":"café"}}`

	tests := []struct {
		name       string
		body       string
		status     int
		decision   string
		ruleID     string
		reason     string
		errSub     string
		forwarded  bool
		exactBytes bool
	}{
		{name: "exactly 500.00 forwarded", body: exact, status: http.StatusOK, forwarded: true, exactBytes: true},
		{name: "one cent under forwarded", body: transfer("49999"), status: http.StatusOK, forwarded: true},
		{name: "one cent forwarded", body: transfer("1"), status: http.StatusOK, forwarded: true},
		{
			name: "500.01 needs approval", body: transfer("50001"), status: http.StatusForbidden,
			decision: string(rules.NeedsApproval), ruleID: "transfer_over_500_needs_approval",
			reason: "transfers over $500.00 need human approval",
		},
		{
			name: "zero denied", body: transfer("0"), status: http.StatusForbidden,
			decision: string(rules.Deny), ruleID: "transfer_amount_must_be_positive",
			reason: "transfer amount must be a positive number of cents",
		},
		{
			name: "negative denied", body: transfer("-1"), status: http.StatusForbidden,
			decision: string(rules.Deny), ruleID: "transfer_amount_must_be_positive",
		},
		{
			name: "negative over 500 is deny", body: transfer("-50001"), status: http.StatusForbidden,
			decision: string(rules.Deny), ruleID: "transfer_amount_must_be_positive",
		},
		{name: "float rejected", body: transfer("500.01"), status: http.StatusBadRequest, errSub: "floating-point"},
		{name: "float 500.00 rejected", body: transfer("500.00"), status: http.StatusBadRequest, errSub: "floating-point"},
		{name: "malformed", body: `{`, status: http.StatusBadRequest, errSub: "malformed JSON"},
		{name: "empty", body: ``, status: http.StatusBadRequest, errSub: "empty body"},
		{name: "unknown tool", body: `{"tool":"wire","arguments":{}}`, status: http.StatusBadRequest, errSub: "unknown tool"},
		{name: "unknown field", body: `{"tool":"transfer","arguments":{"amount":1}}`, status: http.StatusBadRequest, errSub: "unknown field"},
		{name: "missing field", body: `{"tool":"get_balance","arguments":{}}`, status: http.StatusBadRequest, errSub: "missing field"},
		{name: "get balance forwarded", body: `{"tool":"get_balance","arguments":{"account_id":"acct_1"}}`, status: http.StatusOK, forwarded: true},
		{name: "update record forwarded", body: `{"tool":"update_record","arguments":{"record_id":"rec_1","field_name":"status","value":"closed"}}`, status: http.StatusOK, forwarded: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := saw.hits.Load()
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/tool-calls", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			h.ServeHTTP(rec, req)

			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d, body %s", rec.Code, tc.status, rec.Body.String())
			}
			delta := saw.hits.Load() - before
			if tc.forwarded && delta != 1 {
				t.Fatalf("upstream hits = %d, want 1", delta)
			}
			if !tc.forwarded && delta != 0 {
				t.Fatalf("upstream hits = %d, want 0", delta)
			}
			if tc.forwarded {
				if rec.Body.String() != `{"ok":true}` {
					t.Fatalf("body %s", rec.Body.String())
				}
				if rec.Header().Get(proxy.HeaderDecision) != string(rules.Allow) {
					t.Fatal(rec.Header().Get(proxy.HeaderDecision))
				}
				if tc.exactBytes {
					body, method, ct, path := saw.snapshot()
					if body != tc.body {
						t.Fatalf("upstream body = %s", body)
					}
					if method != http.MethodPost || ct != "application/json" || path != "/" {
						t.Fatalf("method %s ct %s path %s", method, ct, path)
					}
				}
				return
			}
			if rec.Header().Get("Content-Type") != "application/json" {
				t.Fatal(rec.Header().Get("Content-Type"))
			}
			if tc.errSub != "" {
				if rec.Header().Get(proxy.HeaderDecision) != "" {
					t.Fatal("schema rejection set a decision header")
				}
				if !strings.Contains(rec.Body.String(), tc.errSub) {
					t.Fatalf("body %s", rec.Body.String())
				}
				return
			}
			if rec.Header().Get(proxy.HeaderDecision) != tc.decision {
				t.Fatal(rec.Header().Get(proxy.HeaderDecision))
			}
			if !strings.Contains(rec.Body.String(), `"decision":"`+tc.decision+`"`) {
				t.Fatalf("body %s", rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), `"forwarded":false`) {
				t.Fatalf("body %s", rec.Body.String())
			}
			if tc.ruleID != "" && !strings.Contains(rec.Body.String(), `"rule_id":"`+tc.ruleID+`"`) {
				t.Fatalf("body %s", rec.Body.String())
			}
			if tc.reason != "" && !strings.Contains(rec.Body.String(), tc.reason) {
				t.Fatalf("body %s", rec.Body.String())
			}
		})
	}
}

func TestProxyForwardsThroughFakeUpstream(t *testing.T) {
	up := httptest.NewServer(fakeupstream.Handler())
	t.Cleanup(up.Close)
	handler, err := proxy.New(loadPolicy(t), up.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	body := transfer("100")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/tool-calls", strings.NewReader(body))
	handler.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != `{"ok":true,"received":`+body+`}` {
		t.Fatalf("body %s", rec.Body.String())
	}
}

func TestProxyUpstreamError(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	t.Cleanup(up.Close)
	handler, err := proxy.New(loadPolicy(t), up.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/tool-calls", strings.NewReader(transfer("100")))
	handler.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d", rec.Code)
	}
	if rec.Body.String() != "nope\n" {
		t.Fatalf("body %q", rec.Body.String())
	}
	if rec.Header().Get(proxy.HeaderDecision) != string(rules.Allow) {
		t.Fatal("upstream failure was not an allow passthrough")
	}
}

func TestProxyUpstreamDown(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := up.URL
	up.Close()
	client := &http.Client{Timeout: time.Second}
	handler, err := proxy.New(loadPolicy(t), url, client)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/tool-calls", strings.NewReader(transfer("100")))
	handler.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "upstream request failed") {
		t.Fatal(rec.Body.String())
	}
	if rec.Header().Get(proxy.HeaderDecision) != string(rules.Allow) {
		t.Fatalf("header %q", rec.Header().Get(proxy.HeaderDecision))
	}
}

func TestProxyUpstreamTooLarge(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.Copy(w, bytes.NewReader(bytes.Repeat([]byte("a"), (1<<20)+1)))
	}))
	t.Cleanup(up.Close)
	handler, err := proxy.New(loadPolicy(t), up.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/tool-calls", strings.NewReader(transfer("100")))
	handler.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "too large") {
		t.Fatal(rec.Body.String())
	}
}

func TestProxyBodyTooLarge(t *testing.T) {
	called := false
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	t.Cleanup(up.Close)
	handler, err := proxy.New(loadPolicy(t), up.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	memo := strings.Repeat("a", 70_000)
	body := `{"tool":"transfer","arguments":{"from_account":"a","to_account":"b","amount_cents":100,"currency":"USD","memo":"` + memo + `"}}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/tool-calls", strings.NewReader(body))
	handler.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if called {
		t.Fatal("large body was forwarded")
	}
}

func TestProxyInternalErrorDoesNotForward(t *testing.T) {
	called := false
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	t.Cleanup(up.Close)
	policy := config.Policy{
		Catalog: schema.Catalog{Tools: map[string]schema.Tool{
			"get_balance": {Fields: map[string]schema.Field{
				"account_id": {Type: schema.TypeString, Required: true},
			}},
		}},
		Rules: []rules.Rule{{
			ID: "bad", Tool: "get_balance", Field: "account_id", Op: rules.OpGt,
			Kind: schema.TypeString, Str: "x", Decision: rules.Deny, Reason: "nope",
		}},
	}
	handler, err := proxy.New(policy, up.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/tool-calls", strings.NewReader(`{"tool":"get_balance","arguments":{"account_id":"acct_1"}}`))
	handler.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != `{"error":"internal error"}` {
		t.Fatal(rec.Body.String())
	}
	if called {
		t.Fatal("forwarded")
	}
}

func TestProxyRoutes(t *testing.T) {
	handler, err := proxy.New(loadPolicy(t), "http://127.0.0.1:9", nil)
	if err != nil {
		t.Fatal(err)
	}
	h := handler.Handler()

	t.Run("health", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		if rec.Code != http.StatusOK || rec.Body.String() != "ok\n" {
			t.Fatalf("status %d body %q", rec.Code, rec.Body.String())
		}
	})
	t.Run("get tool calls", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/tool-calls", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status %d", rec.Code)
		}
	})
	t.Run("unknown path", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/other", strings.NewReader(`{}`)))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status %d", rec.Code)
		}
	})
	t.Run("trailing slash", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/tool-calls/", strings.NewReader(`{}`)))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status %d", rec.Code)
		}
	})
}

func TestNewRejectsBadUpstream(t *testing.T) {
	policy := loadPolicy(t)
	for _, upstream := range []string{"", "not a url", "ftp://example.com", "/relative", "http://", "://bad"} {
		if _, err := proxy.New(policy, upstream, nil); err == nil {
			t.Fatalf("accepted %q", upstream)
		}
	}
	if _, err := proxy.New(policy, "https://example.com/v1/tools", nil); err != nil {
		t.Fatal(err)
	}
}
