package demo_test

import (
	"bytes"
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sinsuki/guardrail-proxy/internal/demo"
)

func TestRun(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	policy := filepath.Join(filepath.Dir(file), "..", "..", "policy.json")
	var buf bytes.Buffer
	if err := demo.Run(context.Background(), &buf, demo.Options{PolicyPath: policy}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"Balance read",
		"Transfer $200.00",
		"approver says approve",
		"approver says deny",
		"approval denied",
		"floating-point",
		"ada@example.com",
		"email=1",
		"ok entries=",
		"bad signature",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q\n%s", want, out)
		}
	}
}
