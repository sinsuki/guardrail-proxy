package fakeapprover_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sinsuki/guardrail-proxy/internal/approval"
	"github.com/sinsuki/guardrail-proxy/internal/fakeapprover"
)

const testSecret = "test-approval-secret"

func TestApproverSignsVerifiedRequest(t *testing.T) {
	call := []byte(`{"tool":"transfer","arguments":{"amount_cents":50001}}`)
	exp := "2030-01-02T03:04:05.5Z"
	raw, err := json.Marshal(approval.Request{
		RequestID:  "req-1",
		Call:       call,
		CallSHA256: approval.Hash(call),
		Reason:     "transfers over $500.00 need human approval",
		RuleID:     "transfer_over_500_needs_approval",
		ExpiresAt:  exp,
	})
	if err != nil {
		t.Fatal(err)
	}

	approver := fakeapprover.New(testSecret, "approve")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw))
	req.Header.Set(approval.SignatureHeader, approval.Sign([]byte(testSecret), raw))
	approver.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.Bytes()
	if rec.Header().Get(approval.SignatureHeader) != approval.Sign([]byte(testSecret), body) {
		t.Fatal("response signature")
	}
	var resp approval.Response
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Decision != "approve" || resp.RequestID != "req-1" || resp.CallSHA256 != approval.Hash(call) || resp.ExpiresAt != exp {
		t.Fatalf("%+v", resp)
	}
}

func TestApproverRejectsBadSignature(t *testing.T) {
	raw := []byte(`{"request_id":"req-1","call":{},"call_sha256":"abc","reason":"r","rule_id":"id","expires_at":"2030-01-02T03:04:05Z"}`)
	approver := fakeapprover.New(testSecret, "approve")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw))
	req.Header.Set(approval.SignatureHeader, approval.Sign([]byte("other-approval-secret"), raw))
	approver.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestApproverRejectsGet(t *testing.T) {
	rec := httptest.NewRecorder()
	fakeapprover.New(testSecret, "deny").Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Allow"), http.MethodPost) {
		t.Fatal(rec.Header().Get("Allow"))
	}
}
