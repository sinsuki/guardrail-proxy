// Package approval asks a webhook to approve one tool call.
// The webhook response is HMAC-signed, single-use, and bound to the exact call bytes.
package approval

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	// SignatureHeader carries an HMAC-SHA256 of the raw body, prefixed with "v1=".
	SignatureHeader = "X-Guardrail-Signature"

	ReasonDenied = "approval denied"

	maxResponse = 64 << 10
	sigPrefix   = "v1="
)

var (
	ErrBadSignature = errors.New("approval signature is invalid")
	ErrMismatch     = errors.New("approval does not match the call")
	ErrReplay       = errors.New("approval already used")
	ErrTimedOut     = errors.New("approval timed out")
	ErrFailed       = errors.New("approval request failed")
)

// Decision is the webhook's answer.
type Decision string

const (
	Approve Decision = "approve"
	Deny    Decision = "deny"
)

// Request is the body posted to the webhook.
type Request struct {
	RequestID  string          `json:"request_id"`
	Call       json.RawMessage `json:"call"`
	CallSHA256 string          `json:"call_sha256"`
	Reason     string          `json:"reason"`
	RuleID     string          `json:"rule_id"`
	ExpiresAt  string          `json:"expires_at"`
}

// Response is the signed body the webhook sends back.
// ExpiresAt and CallSHA256 must echo the request so the decision cannot be
// moved onto a different call or a later deadline.
type Response struct {
	RequestID  string `json:"request_id"`
	Decision   string `json:"decision"`
	CallSHA256 string `json:"call_sha256"`
	ExpiresAt  string `json:"expires_at"`
}

// Pending is the in-flight request a response must match.
type Pending struct {
	ID        string
	CallHash  string
	ExpiresAt string
	Expires   time.Time
}

// Result is the outcome of asking the webhook. Approved is false unless the
// signed decision is approve and every binding check passed.
type Result struct {
	RequestID string
	Approved  bool
	Reason    string
}

// Client posts approval requests and checks the signed response.
type Client struct {
	webhook *url.URL
	secret  []byte
	timeout time.Duration
	http    *http.Client
	used    *Used
}

// NewClient checks the webhook URL and the shared secret.
// The secret is at least 16 bytes. hc may be nil.
func NewClient(webhook, secret string, timeout time.Duration, hc *http.Client) (*Client, error) {
	if timeout <= 0 {
		return nil, errors.New("approval timeout must be positive")
	}
	if len(secret) < 16 {
		return nil, errors.New("approval secret must be at least 16 bytes")
	}
	u, err := url.Parse(webhook)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("approval webhook must be an absolute http or https URL")
	}
	if hc == nil {
		hc = &http.Client{Timeout: timeout}
	}
	return &Client{
		webhook: u,
		secret:  []byte(secret),
		timeout: timeout,
		http:    hc,
		used:    NewUsed(15 * time.Minute),
	}, nil
}

// Ask posts call to the webhook and waits for one signed decision.
// A timeout, a bad signature, a mismatched call, or a replay is not approved.
func (c *Client) Ask(ctx context.Context, call []byte, ruleID, reason string) Result {
	id, err := newID()
	if err != nil {
		return Result{Reason: ErrFailed.Error()}
	}
	deadline := time.Now().Add(c.timeout).UTC()
	pending := Pending{
		ID:        id,
		CallHash:  Hash(call),
		ExpiresAt: deadline.Format(time.RFC3339Nano),
		Expires:   deadline,
	}
	payload, err := json.Marshal(Request{
		RequestID:  pending.ID,
		Call:       json.RawMessage(call),
		CallSHA256: pending.CallHash,
		Reason:     reason,
		RuleID:     ruleID,
		ExpiresAt:  pending.ExpiresAt,
	})
	if err != nil {
		return Result{RequestID: id, Reason: ErrFailed.Error()}
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.webhook.String(), bytes.NewReader(payload))
	if err != nil {
		return Result{RequestID: id, Reason: ErrFailed.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(SignatureHeader, Sign(c.secret, payload))

	resp, err := c.http.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || timedOut(err) {
			return Result{RequestID: id, Reason: ErrTimedOut.Error()}
		}
		return Result{RequestID: id, Reason: ErrFailed.Error()}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return Result{RequestID: id, Reason: ErrFailed.Error()}
	}
	if resp.StatusCode != http.StatusOK || len(body) > maxResponse {
		return Result{RequestID: id, Reason: ErrFailed.Error()}
	}

	decision, err := Check(c.secret, pending, c.used, body, resp.Header.Get(SignatureHeader), time.Now())
	if err != nil {
		return Result{RequestID: id, Reason: err.Error()}
	}
	if decision == Deny {
		return Result{RequestID: id, Reason: ReasonDenied}
	}
	return Result{RequestID: id, Approved: true, Reason: "approved"}
}

// Hash is the SHA-256 hex digest of the exact tool-call bytes that will be forwarded.
func Hash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// Sign returns the SignatureHeader value for body.
func Sign(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return sigPrefix + hex.EncodeToString(mac.Sum(nil))
}

// Check authenticates body and binds it to pending. A valid decision consumes pending.ID.
func Check(secret []byte, pending Pending, used *Used, body []byte, sigHeader string, now time.Time) (Decision, error) {
	if !signatureOK(secret, body, sigHeader) {
		return "", ErrBadSignature
	}
	var resp Response
	if err := unmarshalStrict(body, &resp); err != nil {
		return "", ErrMismatch
	}
	if resp.RequestID != pending.ID || resp.ExpiresAt != pending.ExpiresAt || !sameHash(resp.CallSHA256, pending.CallHash) {
		return "", ErrMismatch
	}
	decision := Decision(resp.Decision)
	if decision != Approve && decision != Deny {
		return "", ErrMismatch
	}
	if now.After(pending.Expires) {
		return "", ErrTimedOut
	}
	if err := used.Consume(pending.ID, now); err != nil {
		return "", err
	}
	return decision, nil
}

func sameHash(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func signatureOK(secret, body []byte, header string) bool {
	if len(header) <= len(sigPrefix) || header[:len(sigPrefix)] != sigPrefix {
		return false
	}
	got, err := hex.DecodeString(header[len(sigPrefix):])
	if err != nil || len(got) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hmac.Equal(got, mac.Sum(nil))
}

func unmarshalStrict(body []byte, dest any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dest); err != nil {
		return err
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("trailing json")
	}
	return nil
}

func timedOut(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

// Used remembers request ids so a signed decision cannot be accepted twice.
type Used struct {
	mu     sync.Mutex
	retain time.Duration
	ids    map[string]time.Time
}

// NewUsed retains consumed ids for retain.
func NewUsed(retain time.Duration) *Used {
	if retain <= 0 {
		retain = 15 * time.Minute
	}
	return &Used{retain: retain, ids: make(map[string]time.Time)}
}

// Consume returns ErrReplay when id was accepted recently.
func (u *Used) Consume(id string, now time.Time) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if exp, ok := u.ids[id]; ok && now.Before(exp) {
		return ErrReplay
	}
	u.ids[id] = now.Add(u.retain)
	if len(u.ids) <= 4096 {
		return nil
	}
	for k, exp := range u.ids {
		if !now.Before(exp) {
			delete(u.ids, k)
		}
	}
	return nil
}
