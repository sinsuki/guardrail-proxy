// Package proxy is an HTTP front door that forwards only allowed tool calls.
package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/sinsuki/guardrail-proxy/internal/approval"
	"github.com/sinsuki/guardrail-proxy/internal/audit"
	"github.com/sinsuki/guardrail-proxy/internal/check"
	"github.com/sinsuki/guardrail-proxy/internal/config"
	"github.com/sinsuki/guardrail-proxy/internal/rules"
	"github.com/sinsuki/guardrail-proxy/internal/schema"
)

const (
	maxRequestBody  = 64 << 10
	maxUpstreamBody = 1 << 20
)

// HeaderDecision is set on allow responses and on rule denials.
// Schema rejections do not set it; those responses carry an error object.
const HeaderDecision = "X-Guardrail-Decision"

// HeaderRequestID is the approval request id, set when a webhook was asked.
const HeaderRequestID = "X-Guardrail-Request-Id"

// Proxy checks tool calls and forwards the ones the policy allows.
// The upstream URL comes from the operator, not from the request.
// Auditor records one audit event. A nil auditor records nothing.
type Auditor interface {
	Append(kind string, payload any) error
}

type Proxy struct {
	checker  *check.Checker
	upstream *url.URL
	client   *http.Client
	approval *approval.Client
	audit    Auditor
}

// Option configures optional proxy behavior.
type Option func(*Proxy)

// WithApproval asks this webhook before forwarding a needs_approval call.
// Without it, needs_approval is not forwarded.
func WithApproval(c *approval.Client) Option {
	return func(p *Proxy) {
		p.approval = c
	}
}

// WithAudit records tool calls, decisions, approvals, and forwards.
func WithAudit(a Auditor) Option {
	return func(p *Proxy) {
		p.audit = a
	}
}

// New builds a proxy. client may be nil, in which case a client with a 10s timeout is used.
func New(policy config.Policy, upstream string, client *http.Client, opts ...Option) (*Proxy, error) {
	u, err := url.Parse(upstream)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("upstream must be an absolute http or https URL")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	p := &Proxy{
		checker:  check.New(policy),
		upstream: u,
		client:   client,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

// Handler serves POST /v1/tool-calls and GET /healthz.
func (p *Proxy) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/tool-calls", p.handleToolCall)
	mux.HandleFunc("GET /healthz", p.handleHealth)
	return mux
}

func (p *Proxy) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok\n")
}

func (p *Proxy) handleToolCall(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(w, r)
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body is too large")
			return
		}
		writeError(w, http.StatusBadRequest, "could not read request body")
		return
	}

	if err := p.record(audit.KindToolCall, map[string]any{
		"body_sha256": bodyHash(body),
		"bytes":       len(body),
	}); err != nil {
		auditFailed(w)
		return
	}

	result, err := p.checker.Check(body)
	if err != nil {
		var rejected *schema.Error
		if errors.As(err, &rejected) {
			log.Printf("rejected error=%s", rejected.Error())
			if err := p.record(audit.KindSchema, map[string]any{"ok": false, "error": rejected.Error()}); err != nil {
				auditFailed(w)
				return
			}
			writeError(w, http.StatusBadRequest, rejected.Error())
			return
		}
		log.Printf("check error=%v", err)
		_ = p.record(audit.KindSchema, map[string]any{"ok": false, "error": "internal"})
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := p.record(audit.KindSchema, map[string]any{"ok": true, "tool": result.Tool}); err != nil {
		auditFailed(w)
		return
	}
	if err := p.record(audit.KindDecision, map[string]any{
		"tool":     result.Tool,
		"decision": string(result.Decision),
		"rule_id":  result.RuleID,
		"reason":   result.Reason,
	}); err != nil {
		auditFailed(w)
		return
	}

	switch result.Decision {
	case rules.Allow:
		p.forward(w, r, body, result)
	case rules.NeedsApproval:
		p.handleApproval(w, r, body, result)
	case rules.Deny:
		log.Printf("decision tool=%s decision=%s rule=%s forwarded=false", result.Tool, result.Decision, result.RuleID)
		w.Header().Set(HeaderDecision, string(result.Decision))
		writeJSON(w, http.StatusForbidden, decisionResponse{
			Decision:  result.Decision,
			Reason:    result.Reason,
			RuleID:    result.RuleID,
			Forwarded: false,
		})
	default:
		log.Printf("unexpected decision %q", result.Decision)
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

func (p *Proxy) handleApproval(w http.ResponseWriter, r *http.Request, body []byte, result rules.Result) {
	if p.approval == nil {
		// No webhook is configured, so the call cannot be approved.
		log.Printf("decision tool=%s decision=%s rule=%s forwarded=false", result.Tool, result.Decision, result.RuleID)
		w.Header().Set(HeaderDecision, string(result.Decision))
		writeJSON(w, http.StatusForbidden, decisionResponse{
			Decision:  result.Decision,
			Reason:    result.Reason,
			RuleID:    result.RuleID,
			Forwarded: false,
		})
		return
	}

	outcome := p.approval.Ask(r.Context(), body, result.RuleID, result.Reason)
	if outcome.RequestID != "" {
		w.Header().Set(HeaderRequestID, outcome.RequestID)
	}
	if err := p.record(audit.KindApprovalRequest, map[string]any{
		"request_id": outcome.RequestID,
		"tool":       result.Tool,
		"rule_id":    result.RuleID,
	}); err != nil {
		auditFailed(w)
		return
	}
	if err := p.record(audit.KindApprovalResult, map[string]any{
		"request_id": outcome.RequestID,
		"approved":   outcome.Approved,
		"reason":     outcome.Reason,
	}); err != nil {
		auditFailed(w)
		return
	}
	if !outcome.Approved {
		log.Printf("approval request_id=%s tool=%s approved=false reason=%s", outcome.RequestID, result.Tool, outcome.Reason)
		w.Header().Set(HeaderDecision, string(rules.Deny))
		writeJSON(w, http.StatusForbidden, decisionResponse{
			Decision:  rules.Deny,
			Reason:    outcome.Reason,
			RuleID:    result.RuleID,
			RequestID: outcome.RequestID,
			Forwarded: false,
		})
		return
	}
	log.Printf("approval request_id=%s tool=%s approved=true", outcome.RequestID, result.Tool)
	p.forward(w, r, body, result)
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, body []byte, result rules.Result) {
	// The policy already allowed this call. A later failure is transport, not a deny.
	w.Header().Set(HeaderDecision, string(rules.Allow))
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, p.upstream.String(), bytes.NewReader(body))
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream request failed")
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		log.Printf("upstream error=%v", err)
		if err := p.record(audit.KindForward, map[string]any{"target": "upstream", "status": 0, "bytes": 0}); err != nil {
			auditFailed(w)
			return
		}
		writeError(w, http.StatusBadGateway, "upstream request failed")
		return
	}
	defer resp.Body.Close()

	upstreamBody, err := io.ReadAll(io.LimitReader(resp.Body, maxUpstreamBody+1))
	if err != nil {
		log.Printf("upstream read error=%v", err)
		writeError(w, http.StatusBadGateway, "upstream request failed")
		return
	}
	if len(upstreamBody) > maxUpstreamBody {
		log.Printf("upstream response exceeds %d bytes", maxUpstreamBody)
		writeError(w, http.StatusBadGateway, "upstream response is too large")
		return
	}

	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/octet-stream"
	}
	if err := p.record(audit.KindForward, map[string]any{
		"target": "upstream",
		"status": resp.StatusCode,
		"bytes":  len(upstreamBody),
	}); err != nil {
		auditFailed(w)
		return
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set(HeaderDecision, string(rules.Allow))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(upstreamBody)
	log.Printf("decision tool=%s decision=%s forwarded=true upstream_status=%d", result.Tool, rules.Allow, resp.StatusCode)
}

func (p *Proxy) record(kind string, payload any) error {
	if p.audit == nil {
		return nil
	}
	if err := p.audit.Append(kind, payload); err != nil {
		log.Printf("audit error=%v", err)
		return err
	}
	return nil
}

func auditFailed(w http.ResponseWriter) {
	writeError(w, http.StatusInternalServerError, "audit log failed")
}

func bodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	defer r.Body.Close()
	return io.ReadAll(r.Body)
}

type decisionResponse struct {
	Decision  rules.Decision `json:"decision"`
	Reason    string         `json:"reason"`
	RuleID    string         `json:"rule_id,omitempty"`
	RequestID string         `json:"request_id,omitempty"`
	Forwarded bool           `json:"forwarded"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, errorResponse{Error: message})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
