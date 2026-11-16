package approval_test

import (
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sinsuki/guardrail-proxy/internal/approval"
)

const testSecret = "test-approval-secret"

func callBody(amount string) []byte {
	return []byte(`{"tool":"transfer","arguments":{"from_account":"acct_1","to_account":"acct_2","amount_cents":` + amount + `,"currency":"USD"}}`)
}

func newPending(body []byte, when time.Time) approval.Pending {
	when = when.UTC()
	return approval.Pending{
		ID:        "11111111-1111-4111-8111-111111111111",
		CallHash:  approval.Hash(body),
		ExpiresAt: when.Format(time.RFC3339Nano),
		Expires:   when,
	}
}

func signedResponse(secret string, pending approval.Pending, decision, hash string) ([]byte, string) {
	if hash == "" {
		hash = pending.CallHash
	}
	raw, err := json.Marshal(approval.Response{
		RequestID:  pending.ID,
		Decision:   decision,
		CallSHA256: hash,
		ExpiresAt:  pending.ExpiresAt,
	})
	if err != nil {
		panic(err)
	}
	return raw, approval.Sign([]byte(secret), raw)
}

func TestCheck(t *testing.T) {
	now := time.Now().UTC()
	body := callBody("50001")
	other := callBody("50002")
	if approval.Hash(body) == approval.Hash(other) {
		t.Fatal("different amounts hashed the same")
	}

	tests := []struct {
		name     string
		decision string
		secret   string
		hash     string
		expires  time.Time
		repeat   int
		want     approval.Decision
		wantErr  error
		changeID bool
	}{
		{name: "approve", decision: "approve", secret: testSecret, expires: now.Add(time.Minute), want: approval.Approve},
		{name: "deny", decision: "deny", secret: testSecret, expires: now.Add(time.Minute), want: approval.Deny},
		{name: "bad signature", decision: "approve", secret: "other-approval-secret", expires: now.Add(time.Minute), wantErr: approval.ErrBadSignature},
		{name: "tampered amount", decision: "approve", secret: testSecret, hash: approval.Hash(other), expires: now.Add(time.Minute), wantErr: approval.ErrMismatch},
		{name: "replay", decision: "approve", secret: testSecret, expires: now.Add(time.Minute), repeat: 2, wantErr: approval.ErrReplay},
		{name: "expired", decision: "approve", secret: testSecret, expires: now.Add(-time.Second), wantErr: approval.ErrTimedOut},
		{name: "wrong request id", decision: "approve", secret: testSecret, expires: now.Add(time.Minute), changeID: true, wantErr: approval.ErrMismatch},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pending := newPending(body, tc.expires)
			raw, sig := signedResponse(tc.secret, pending, tc.decision, tc.hash)
			if tc.changeID {
				pending.ID = "22222222-2222-4222-8222-222222222222"
			}
			used := approval.NewUsed(time.Minute)
			calls := tc.repeat
			if calls == 0 {
				calls = 1
			}
			var decision approval.Decision
			var err error
			for i := 0; i < calls; i++ {
				decision, err = approval.Check([]byte(testSecret), pending, used, raw, sig, now)
				if i < calls-1 && err != nil {
					t.Fatalf("call %d: %v", i, err)
				}
			}
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if decision != tc.want {
				t.Fatalf("decision = %s, want %s", decision, tc.want)
			}
		})
	}
}

func TestConsumeOnceUnderRace(t *testing.T) {
	now := time.Now().UTC()
	body := callBody("50001")
	pending := newPending(body, now.Add(time.Minute))
	raw, sig := signedResponse(testSecret, pending, "approve", "")
	used := approval.NewUsed(time.Minute)
	var ok atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := approval.Check([]byte(testSecret), pending, used, raw, sig, now)
			if err == nil {
				ok.Add(1)
				return
			}
			if !errors.Is(err, approval.ErrReplay) {
				t.Errorf("err = %v", err)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("accepted %d times", ok.Load())
	}
}

func TestNewClientRejects(t *testing.T) {
	tests := []struct {
		name    string
		webhook string
		secret  string
		timeout time.Duration
	}{
		{name: "short secret", webhook: "http://127.0.0.1:9/approve", secret: "too-short", timeout: time.Second},
		{name: "empty secret", webhook: "http://127.0.0.1:9/approve", secret: "", timeout: time.Second},
		{name: "zero timeout", webhook: "http://127.0.0.1:9/approve", secret: testSecret, timeout: 0},
		{name: "ftp", webhook: "ftp://example.com/approve", secret: testSecret, timeout: time.Second},
		{name: "relative", webhook: "/approve", secret: testSecret, timeout: time.Second},
		{name: "missing host", webhook: "http://", secret: testSecret, timeout: time.Second},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := approval.NewClient(tc.webhook, tc.secret, tc.timeout, nil); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	if _, err := approval.NewClient("https://example.com/approve", testSecret, time.Second, nil); err != nil {
		t.Fatal(err)
	}
}
