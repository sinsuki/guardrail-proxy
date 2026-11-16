// Package proxy is an HTTP front door that forwards only allowed tool calls.
package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

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

// Proxy checks tool calls and forwards the ones the policy allows.
// The upstream URL comes from the operator, not from the request.
type Proxy struct {
	checker  *check.Checker
	upstream *url.URL
	client   *http.Client
}

// New builds a proxy. client may be nil, in which case a client with a 10s timeout is used.
func New(policy config.Policy, upstream string, client *http.Client) (*Proxy, error) {
	u, err := url.Parse(upstream)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("upstream must be an absolute http or https URL")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Proxy{
		checker:  check.New(policy),
		upstream: u,
		client:   client,
	}, nil
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

	result, err := p.checker.Check(body)
	if err != nil {
		var rejected *schema.Error
		if errors.As(err, &rejected) {
			log.Printf("rejected error=%s", rejected.Error())
			writeError(w, http.StatusBadRequest, rejected.Error())
			return
		}
		log.Printf("check error=%v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	switch result.Decision {
	case rules.Allow:
		p.forward(w, r, body, result)
	case rules.Deny, rules.NeedsApproval:
		// needs_approval is not executed in this milestone. A later milestone
		// can hold the call and wait for an approval webhook. The decision
		// stays needs_approval so a hard deny and a missing approval are distinct.
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
	w.Header().Set("Content-Type", ct)
	w.Header().Set(HeaderDecision, string(rules.Allow))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(upstreamBody)
	log.Printf("decision tool=%s decision=%s forwarded=true upstream_status=%d", result.Tool, result.Decision, resp.StatusCode)
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
