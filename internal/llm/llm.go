// Package llm redacts a prompt, forwards it to a model URL, and restores
// placeholders in the reply. The mapping never leaves this process.
package llm

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/sinsuki/guardrail-proxy/internal/redact"
)

const (
	maxBody = 1 << 20
	// HeaderRedacted lists how many values of each kind were replaced.
	// It does not contain the values.
	HeaderRedacted = "X-Guardrail-Redacted"
)

// Proxy forwards redacted prompts to an LLM URL.
type Proxy struct {
	upstream *url.URL
	client   *http.Client
}

// New builds a proxy. client may be nil.
func New(upstream string, client *http.Client) (*Proxy, error) {
	u, err := url.Parse(upstream)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("llm url must be an absolute http or https URL")
	}
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	return &Proxy{upstream: u, client: client}, nil
}

// Handler serves POST /v1/llm.
func (p *Proxy) Handler() http.Handler {
	return http.HandlerFunc(p.serve)
}

func (p *Proxy) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := readBody(w, r)
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeErr(w, http.StatusRequestEntityTooLarge, "request body is too large")
			return
		}
		writeErr(w, http.StatusBadRequest, "could not read request body")
		return
	}

	outbound, vault, contentType, err := redactBody(body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "request JSON is malformed")
		return
	}
	w.Header().Set(HeaderRedacted, formatCounts(vault))

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, p.upstream.String(), bytes.NewReader(outbound))
	if err != nil {
		writeErr(w, http.StatusBadGateway, "llm request failed")
		return
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := p.client.Do(req)
	if err != nil {
		log.Printf("llm error=%v", err)
		writeErr(w, http.StatusBadGateway, "llm request failed")
		return
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil || len(respBody) > maxBody {
		writeErr(w, http.StatusBadGateway, "llm response failed")
		return
	}
	restored := []byte(vault.Restore(string(respBody)))
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/json"
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(restored)
	log.Printf("llm redacted=%s status=%d", formatCounts(vault), resp.StatusCode)
}

func redactBody(body []byte) ([]byte, *redact.Vault, string, error) {
	trim := bytes.TrimSpace(body)
	if len(trim) > 0 && (trim[0] == '{' || trim[0] == '[') {
		out, vault, err := redact.RedactJSON(body)
		if err != nil {
			return nil, nil, "", err
		}
		return out, vault, "application/json", nil
	}
	text, vault := redact.Redact(string(body))
	return []byte(text), vault, "text/plain; charset=utf-8", nil
}

func formatCounts(v *redact.Vault) string {
	counts := v.Counts()
	if len(counts) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, string(k))
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, strings.ToLower(k)+"="+itoa(counts[redact.Kind(k)]))
	}
	return strings.Join(parts, ",")
}

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	defer r.Body.Close()
	return io.ReadAll(r.Body)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + msg + `"}`))
}
