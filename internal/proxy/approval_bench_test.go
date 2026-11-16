package proxy_test

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sinsuki/guardrail-proxy/internal/approval"
	"github.com/sinsuki/guardrail-proxy/internal/fakeapprover"
	"github.com/sinsuki/guardrail-proxy/internal/proxy"
)

func BenchmarkProxy(b *testing.B) {
	log.SetOutput(io.Discard)
	b.Cleanup(func() { log.SetOutput(os.Stderr) })

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer up.Close()
	approver := fakeapprover.New(approvalSecret, "approve")
	webhook := httptest.NewServer(approver.Handler())
	defer webhook.Close()
	policy := loadPolicy(b)

	b.Run("allow_no_webhook", func(b *testing.B) {
		transport := &http.Transport{}
		b.Cleanup(transport.CloseIdleConnections)
		handler, err := proxy.New(policy, up.URL, &http.Client{Transport: transport})
		if err != nil {
			b.Fatal(err)
		}
		h := handler.Handler()
		body := transfer("50000")
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/tool-calls", strings.NewReader(body))
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				b.Fatalf("status %d %s", rec.Code, rec.Body.String())
			}
		}
	})

	b.Run("approved_over_500", func(b *testing.B) {
		transport := &http.Transport{}
		b.Cleanup(transport.CloseIdleConnections)
		httpClient := &http.Client{Transport: transport}
		client, err := approval.NewClient(webhook.URL, approvalSecret, 2*time.Second, httpClient)
		if err != nil {
			b.Fatal(err)
		}
		handler, err := proxy.New(policy, up.URL, httpClient, proxy.WithApproval(client))
		if err != nil {
			b.Fatal(err)
		}
		h := handler.Handler()
		body := transfer("50001")
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/tool-calls", strings.NewReader(body))
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				b.Fatalf("status %d %s", rec.Code, rec.Body.String())
			}
		}
	})
}
