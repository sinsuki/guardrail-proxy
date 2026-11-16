package fakeupstream_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sinsuki/guardrail-proxy/internal/fakeupstream"
)

func TestHandlerEchoesPost(t *testing.T) {
	body := `{"tool":"transfer","arguments":{"amount_cents":50000}}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	rec := httptest.NewRecorder()
	fakeupstream.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Fatal(rec.Header().Get("Content-Type"))
	}
	if rec.Body.String() != `{"ok":true,"received":`+body+`}` {
		t.Fatalf("body %s", rec.Body.String())
	}
}

func TestHandlerRejectsGet(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	fakeupstream.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Allow"), http.MethodPost) {
		t.Fatal(rec.Header().Get("Allow"))
	}
}

func TestHandlerRejectsLargeBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("a", (1<<20)+1)))
	rec := httptest.NewRecorder()
	fakeupstream.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
}
