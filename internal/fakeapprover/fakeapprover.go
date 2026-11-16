// Package fakeapprover is a stand-in approval webhook for tests and local runs.
// It checks the request HMAC and returns one signed approve or deny.
package fakeapprover

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/sinsuki/guardrail-proxy/internal/approval"
)

const maxBody = 64 << 10

// Approver responds to approval requests.
// Delay, a bad signing secret, a tampered call hash, and response replay are
// test controls. A local run leaves them unset.
type Approver struct {
	secret []byte

	mu         sync.Mutex
	decision   string
	delay      time.Duration
	signSecret []byte
	tamperHash bool
	replay     bool
	lastBody   []byte
	lastSig    string
	lastReq    []byte
	hits       int
}

// New returns an approver that signs with secret.
// decision is "approve" or "deny".
func New(secret, decision string) *Approver {
	if decision != string(approval.Approve) && decision != string(approval.Deny) {
		decision = string(approval.Deny)
	}
	return &Approver{
		secret:     []byte(secret),
		decision:   decision,
		signSecret: []byte(secret),
	}
}

// SetDelay waits before answering. The wait stops if the client goes away.
func (a *Approver) SetDelay(d time.Duration) {
	a.mu.Lock()
	a.delay = d
	a.mu.Unlock()
}

// SetSignSecret signs responses with secret. A different secret produces a bad signature.
func (a *Approver) SetSignSecret(secret string) {
	a.mu.Lock()
	a.signSecret = []byte(secret)
	a.mu.Unlock()
}

// SetTamperHash puts a hash of a different call into an otherwise signed response.
func (a *Approver) SetTamperHash(v bool) {
	a.mu.Lock()
	a.tamperHash = v
	a.mu.Unlock()
}

// SetReplay answers with the previous signed response.
func (a *Approver) SetReplay(v bool) {
	a.mu.Lock()
	a.replay = v
	a.mu.Unlock()
}

// Hits is the number of POSTs received.
func (a *Approver) Hits() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.hits
}

// LastRequest is the last verified approval request body.
func (a *Approver) LastRequest() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]byte(nil), a.lastReq...)
}

// Handler serves the webhook.
func (a *Approver) Handler() http.Handler {
	return http.HandlerFunc(a.serve)
}

func (a *Approver) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		http.Error(w, "request body is too large", http.StatusRequestEntityTooLarge)
		return
	}

	a.mu.Lock()
	a.hits++
	replay := a.replay
	lastBody, lastSig := a.lastBody, a.lastSig
	delay := a.delay
	a.mu.Unlock()

	if replay && lastBody != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(approval.SignatureHeader, lastSig)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(lastBody)
		return
	}

	var req approval.Request
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || !signatureOK(a.secret, body, r.Header.Get(approval.SignatureHeader)) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if approval.Hash(req.Call) != req.CallSHA256 || req.RequestID == "" || req.ExpiresAt == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if delay > 0 {
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-r.Context().Done():
			timer.Stop()
			return
		}
	}

	a.mu.Lock()
	decision := a.decision
	signSecret := append([]byte(nil), a.signSecret...)
	tamper := a.tamperHash
	a.mu.Unlock()

	resp := approval.Response{
		RequestID:  req.RequestID,
		Decision:   decision,
		CallSHA256: req.CallSHA256,
		ExpiresAt:  req.ExpiresAt,
	}
	if tamper {
		resp.CallSHA256 = approval.Hash([]byte(`{"tool":"transfer","arguments":{"amount_cents":1}}`))
	}
	raw, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sig := approval.Sign(signSecret, raw)

	a.mu.Lock()
	a.lastBody = raw
	a.lastSig = sig
	a.lastReq = append([]byte(nil), body...)
	a.mu.Unlock()

	log.Printf("request_id=%s decision=%s", req.RequestID, decision)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(approval.SignatureHeader, sig)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func signatureOK(secret, body []byte, header string) bool {
	return header != "" && header == approval.Sign(secret, body)
}
