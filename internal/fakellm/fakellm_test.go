package fakellm_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sinsuki/guardrail-proxy/internal/fakellm"
)

func TestHandlerEchoesPlaceholder(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"content":"mail [EMAIL_1]"}`))
	rec := httptest.NewRecorder()
	fakellm.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `[EMAIL_1]`) {
		t.Fatalf("%s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"to":"[EMAIL_1]"`) {
		t.Fatalf("%s", rec.Body.String())
	}
}

func TestHandlerRejectsGet(t *testing.T) {
	rec := httptest.NewRecorder()
	fakellm.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d", rec.Code)
	}
}
