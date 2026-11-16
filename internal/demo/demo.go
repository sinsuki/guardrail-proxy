// Package demo runs the scripted walkthrough of the proxy.
// The default path uses local stand-ins and needs no API key.
package demo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sinsuki/guardrail-proxy/internal/approval"
	"github.com/sinsuki/guardrail-proxy/internal/audit"
	"github.com/sinsuki/guardrail-proxy/internal/config"
	"github.com/sinsuki/guardrail-proxy/internal/fakeapprover"
	"github.com/sinsuki/guardrail-proxy/internal/fakellm"
	"github.com/sinsuki/guardrail-proxy/internal/fakeupstream"
	"github.com/sinsuki/guardrail-proxy/internal/llm"
	"github.com/sinsuki/guardrail-proxy/internal/proxy"
)

const approvalSecret = "demo-approval-secret"

// Options controls the walkthrough. An empty LLMURL uses the local stand-in model.
type Options struct {
	PolicyPath string
	LLMURL     string
	LLMKey     string
	LLMModel   string
}

// Run starts the stand-ins and the proxy, plays the scenario, and writes the narration to out.
func Run(ctx context.Context, out io.Writer, opt Options) error {
	if opt.PolicyPath == "" {
		return errors.New("policy path is empty")
	}
	if opt.LLMModel == "" {
		opt.LLMModel = "demo"
	}
	prevLog := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(prevLog)

	dir, err := os.MkdirTemp("", "guardrail-demo-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	keyPath := dir + "/audit.key"
	pubPath := dir + "/audit.pub"
	logPath := dir + "/audit.jsonl"
	if err := audit.GenerateKey(keyPath, pubPath); err != nil {
		return err
	}
	priv, err := audit.LoadPrivate(keyPath)
	if err != nil {
		return err
	}
	recorder, err := audit.Open(logPath, priv)
	if err != nil {
		return err
	}

	bank, err := serve(fakeupstream.Handler())
	if err != nil {
		recorder.Close()
		return err
	}
	defer bank.Shutdown(context.Background())

	approver := fakeapprover.New(approvalSecret, "approve")
	approveSrv, err := serve(approver.Handler())
	if err != nil {
		recorder.Close()
		return err
	}
	defer approveSrv.Shutdown(context.Background())

	llmURL := opt.LLMURL
	var llmName string
	if llmURL == "" {
		fake, err := serve(fakellm.Handler())
		if err != nil {
			recorder.Close()
			return err
		}
		defer fake.Shutdown(context.Background())
		llmURL = fake.URL
		llmName = "the local stand-in"
		opt.LLMModel = "demo"
	} else {
		llmName = opt.LLMURL
		if opt.LLMModel == "" {
			opt.LLMModel = "gpt-4o-mini"
		}
	}

	policy, err := config.Load(opt.PolicyPath)
	if err != nil {
		recorder.Close()
		return err
	}
	approvals, err := approval.NewClient(approveSrv.URL, approvalSecret, 5*time.Second, nil)
	if err != nil {
		recorder.Close()
		return err
	}
	gate, err := proxy.New(policy, bank.URL, nil, proxy.WithApproval(approvals), proxy.WithAudit(recorder))
	if err != nil {
		recorder.Close()
		return err
	}
	model, err := llm.New(llmURL, &http.Client{Timeout: 60 * time.Second}, llm.WithAudit(recorder))
	if err != nil {
		recorder.Close()
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("POST /v1/llm", model.Handler())
	mux.Handle("/", gate.Handler())
	front, err := serve(mux)
	if err != nil {
		recorder.Close()
		return err
	}
	defer front.Shutdown(context.Background())

	client := &http.Client{Timeout: 30 * time.Second}
	fmt.Fprintf(out, "guardrail-proxy demo\n\n")
	if opt.LLMURL == "" {
		fmt.Fprintf(out, "No API key. The bank, the approver, and the model are local stand-ins.\n")
	} else {
		fmt.Fprintf(out, "Prompts go to %s. The bearer token is not printed.\n", opt.LLMURL)
	}
	fmt.Fprintf(out, "Proxy %s\n\n", front.URL)

	steps := []struct {
		title string
		fn    func() error
	}{
		{"1. Balance read", func() error {
			return toolStep(ctx, out, client, front.URL, "get_balance", map[string]any{"account_id": "acct_1"}, 200, "allow",
				"The call matches the schema and no rule denies it, so it is forwarded.")
		}},
		{"2. Transfer $200.00", func() error {
			return toolStep(ctx, out, client, front.URL, "transfer", transferArgs(20000), 200, "allow",
				"20000 cents is $200.00, under the $500.00 threshold, so the rule allows it.")
		}},
		{"3. Transfer $750.00, approver says approve", func() error {
			approver.SetDecision("approve")
			return toolStep(ctx, out, client, front.URL, "transfer", transferArgs(75000), 200, "allow",
				"75000 cents is over $500.00, so the rule asks for approval. The webhook signed approve, and the transfer was forwarded.")
		}},
		{"4. Transfer $750.00, approver says deny", func() error {
			approver.SetDecision("deny")
			return toolStep(ctx, out, client, front.URL, "transfer", transferArgs(75000), 403, "deny",
				"The same amount, with the webhook set to deny. The proxy does not forward it.")
		}},
		{"5. Float amount, rejected", func() error {
			raw := []byte(`{"tool":"transfer","arguments":{"from_account":"acct_1","to_account":"acct_2","amount_cents":200.00,"currency":"USD"}}`)
			resp, err := post(ctx, client, front.URL+"/v1/tool-calls", raw, "")
			if err != nil {
				return err
			}
			printResp(out, resp)
			if resp.status != 400 || !strings.Contains(resp.body, "floating-point") {
				return fmt.Errorf("float call: status %d body %s", resp.status, resp.body)
			}
			fmt.Fprintf(out, "  200.00 is a JSON float. Money has to be integer cents, so the schema rejects it before any rule runs.\n\n")
			return nil
		}},
		{"6. Prompt with an email address", func() error {
			payload := map[string]any{
				"model": opt.LLMModel,
				"messages": []map[string]string{{
					"role":    "user",
					"content": "Please email ada@example.com about the $200 transfer.",
				}},
			}
			raw, err := json.Marshal(payload)
			if err != nil {
				return err
			}
			resp, err := post(ctx, client, front.URL+"/v1/llm", raw, opt.LLMKey)
			if err != nil {
				return err
			}
			printResp(out, resp)
			if resp.status != 200 {
				return fmt.Errorf("llm status %d body %s", resp.status, resp.body)
			}
			if !strings.Contains(resp.header.Get("X-Guardrail-Redacted"), "email=1") {
				return fmt.Errorf("redaction header %q", resp.header.Get("X-Guardrail-Redacted"))
			}
			if opt.LLMURL == "" && !strings.Contains(resp.body, "ada@example.com") {
				return fmt.Errorf("reply did not restore the email: %s", resp.body)
			}
			fmt.Fprintf(out, "  The proxy told us email=1, so the address was replaced before %s saw the prompt.\n", llmName)
			if strings.Contains(resp.body, "ada@example.com") {
				fmt.Fprintf(out, "  The reply contains ada@example.com again. The placeholder was filled back in inside the proxy.\n\n")
			} else {
				fmt.Fprintf(out, "  The model did not echo the placeholder, so there was nothing to fill back in.\n\n")
			}
			return nil
		}},
	}
	for _, step := range steps {
		fmt.Fprintf(out, "%s\n", step.title)
		if err := step.fn(); err != nil {
			recorder.Close()
			return err
		}
	}

	if err := recorder.Close(); err != nil {
		return err
	}
	fmt.Fprintf(out, "7. audit verify\n")
	n, err := audit.Verify(logPath, pubPath)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "  ok entries=%d\n", n)
	fmt.Fprintf(out, "  The chain of %d signed entries checks out.\n\n", n)

	fmt.Fprintf(out, "8. Tamper one byte, then verify again\n")
	if err := tamperLog(logPath); err != nil {
		return err
	}
	_, err = audit.Verify(logPath, pubPath)
	if err == nil {
		return errors.New("verify accepted a tampered log")
	}
	fmt.Fprintf(out, "  %s\n", err.Error())
	fmt.Fprintf(out, "  One changed byte in a signed line is enough. verify stops at the first bad entry.\n")
	return nil
}

func toolStep(ctx context.Context, out io.Writer, client *http.Client, base, tool string, args map[string]any, wantStatus int, wantDecision, note string) error {
	raw, err := json.Marshal(map[string]any{"tool": tool, "arguments": args})
	if err != nil {
		return err
	}
	resp, err := post(ctx, client, base+"/v1/tool-calls", raw, "")
	if err != nil {
		return err
	}
	printResp(out, resp)
	if resp.status != wantStatus {
		return fmt.Errorf("%s: status %d body %s", tool, resp.status, resp.body)
	}
	if got := resp.header.Get("X-Guardrail-Decision"); got != wantDecision {
		return fmt.Errorf("%s: decision %q", tool, got)
	}
	fmt.Fprintf(out, "  %s\n\n", note)
	return nil
}

func transferArgs(cents int) map[string]any {
	return map[string]any{
		"from_account": "acct_1",
		"to_account":   "acct_2",
		"amount_cents": cents,
		"currency":     "USD",
	}
}

type reply struct {
	status int
	header http.Header
	body   string
}

func post(ctx context.Context, client *http.Client, url string, body []byte, bearer string) (reply, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return reply{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		return reply{}, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return reply{}, err
	}
	return reply{status: resp.StatusCode, header: resp.Header.Clone(), body: string(b)}, nil
}

func printResp(out io.Writer, resp reply) {
	decision := resp.header.Get("X-Guardrail-Decision")
	if decision == "" {
		decision = "-"
	}
	fmt.Fprintf(out, "  %d  decision=%s\n", resp.status, decision)
	if red := resp.header.Get("X-Guardrail-Redacted"); red != "" {
		fmt.Fprintf(out, "  redacted=%s\n", red)
	}
	fmt.Fprintf(out, "  %s\n", oneLine(resp.body, 420))
}

func oneLine(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func tamperLog(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	i := bytes.Index(b, []byte(`"ok":true`))
	if i < 0 {
		return errors.New("audit log has no schema success to tamper")
	}
	b[i+5] = 'f'
	return os.WriteFile(path, b, 0600)
}

type listenerServer struct {
	*http.Server
	URL string
}

func serve(h http.Handler) (*listenerServer, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	srv := &http.Server{Handler: h, ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = srv.Serve(ln) }()
	return &listenerServer{Server: srv, URL: "http://" + ln.Addr().String()}, nil
}
