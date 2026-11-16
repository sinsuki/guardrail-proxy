package proxy_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sinsuki/guardrail-proxy/internal/approval"
	"github.com/sinsuki/guardrail-proxy/internal/fakeapprover"
	"github.com/sinsuki/guardrail-proxy/internal/proxy"
)

const approvalSecret = "test-approval-secret"

func TestApprovalWebhook(t *testing.T) {
	var hits atomic.Int32
	var mu sync.Mutex
	var gotBody string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("upstream read: %v", err)
			return
		}
		mu.Lock()
		gotBody = string(b)
		mu.Unlock()
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(up.Close)

	body := transfer("50001")
	tests := []struct {
		name       string
		decision   string
		delay      time.Duration
		timeout    time.Duration
		signSecret string
		tamper     bool
		replay     bool
		wantStatus int
		wantHeader string
		wantReason string
		forward    bool
	}{
		{name: "approve", decision: "approve", timeout: time.Second, wantStatus: http.StatusOK, wantHeader: "allow", forward: true},
		{name: "deny", decision: "deny", timeout: time.Second, wantStatus: http.StatusForbidden, wantHeader: "deny", wantReason: "approval denied"},
		{name: "timeout", decision: "approve", delay: time.Second, timeout: 200 * time.Millisecond, wantStatus: http.StatusForbidden, wantHeader: "deny", wantReason: "approval timed out"},
		{name: "bad signature", decision: "approve", signSecret: "other-approval-secret", timeout: time.Second, wantStatus: http.StatusForbidden, wantHeader: "deny", wantReason: "approval signature is invalid"},
		{name: "replay", decision: "approve", replay: true, timeout: time.Second, wantStatus: http.StatusForbidden, wantHeader: "deny", wantReason: "approval does not match the call"},
		{name: "tampered amount", decision: "approve", tamper: true, timeout: time.Second, wantStatus: http.StatusForbidden, wantHeader: "deny", wantReason: "approval does not match the call"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			approver := fakeapprover.New(approvalSecret, tc.decision)
			if tc.delay > 0 {
				approver.SetDelay(tc.delay)
			}
			if tc.signSecret != "" {
				approver.SetSignSecret(tc.signSecret)
			}
			if tc.tamper {
				approver.SetTamperHash(true)
			}
			webhook := httptest.NewServer(approver.Handler())
			t.Cleanup(webhook.Close)
			client, err := approval.NewClient(webhook.URL, approvalSecret, tc.timeout, &http.Client{})
			if err != nil {
				t.Fatal(err)
			}
			handler, err := proxy.New(loadPolicy(t), up.URL, &http.Client{}, proxy.WithApproval(client))
			if err != nil {
				t.Fatal(err)
			}

			post := func() *httptest.ResponseRecorder {
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodPost, "/v1/tool-calls", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				handler.Handler().ServeHTTP(rec, req)
				return rec
			}

			if tc.replay {
				prime := post()
				if prime.Code != http.StatusOK {
					t.Fatalf("prime status %d body %s", prime.Code, prime.Body.String())
				}
				approver.SetReplay(true)
			}

			before := hits.Load()
			rec := post()
			if rec.Code != tc.wantStatus {
				t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
			}
			if rec.Header().Get(proxy.HeaderDecision) != tc.wantHeader {
				t.Fatalf("header %q", rec.Header().Get(proxy.HeaderDecision))
			}
			if rec.Header().Get(proxy.HeaderRequestID) == "" {
				t.Fatal("missing request id")
			}
			delta := hits.Load() - before
			if tc.forward {
				if delta != 1 {
					t.Fatalf("upstream hits %d", delta)
				}
				if rec.Body.String() != `{"ok":true}` {
					t.Fatalf("body %s", rec.Body.String())
				}
				mu.Lock()
				forwarded := gotBody
				mu.Unlock()
				if forwarded != body {
					t.Fatalf("upstream body %s", forwarded)
				}
				var sent approval.Request
				if err := json.Unmarshal(approver.LastRequest(), &sent); err != nil {
					t.Fatal(err)
				}
				if sent.CallSHA256 != approval.Hash([]byte(body)) {
					t.Fatalf("hash %s", sent.CallSHA256)
				}
				if !strings.Contains(string(sent.Call), `"amount_cents":50001`) {
					t.Fatalf("call %s", sent.Call)
				}
				if sent.Reason != "transfers over $500.00 need human approval" {
					t.Fatal(sent.Reason)
				}
				return
			}
			if delta != 0 {
				t.Fatalf("upstream hits %d", delta)
			}
			if !strings.Contains(rec.Body.String(), `"forwarded":false`) {
				t.Fatalf("body %s", rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.wantReason) {
				t.Fatalf("body %s", rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), `"decision":"deny"`) {
				t.Fatalf("body %s", rec.Body.String())
			}
		})
	}
}

func TestApprovalSkipsAllowAndHardDeny(t *testing.T) {
	var hits atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(up.Close)
	approver := fakeapprover.New(approvalSecret, "approve")
	webhook := httptest.NewServer(approver.Handler())
	t.Cleanup(webhook.Close)
	client, err := approval.NewClient(webhook.URL, approvalSecret, time.Second, &http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := proxy.New(loadPolicy(t), up.URL, nil, proxy.WithApproval(client))
	if err != nil {
		t.Fatal(err)
	}
	post := func(amount string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/tool-calls", strings.NewReader(transfer(amount)))
		handler.Handler().ServeHTTP(rec, req)
		return rec
	}
	if rec := post("50000"); rec.Code != http.StatusOK {
		t.Fatalf("allow status %d %s", rec.Code, rec.Body.String())
	}
	if rec := post("-1"); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"decision":"deny"`) {
		t.Fatalf("deny status %d %s", rec.Code, rec.Body.String())
	}
	if approver.Hits() != 0 {
		t.Fatalf("approver hits %d", approver.Hits())
	}
	if hits.Load() != 1 {
		t.Fatalf("upstream hits %d", hits.Load())
	}
}
