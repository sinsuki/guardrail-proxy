package check_test

import (
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/sinsuki/guardrail-proxy/internal/check"
	"github.com/sinsuki/guardrail-proxy/internal/config"
	"github.com/sinsuki/guardrail-proxy/internal/rules"
	"github.com/sinsuki/guardrail-proxy/internal/schema"
)

func policyPath(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "policy.json")
}

func loadChecker(t testing.TB) *check.Checker {
	t.Helper()
	policy, err := config.Load(policyPath(t))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	return check.New(policy)
}

func transfer(amount string) string {
	return `{"tool":"transfer","arguments":{"from_account":"acct_1","to_account":"acct_2","amount_cents":` + amount + `,"currency":"USD"}}`
}

func TestSamplePolicy(t *testing.T) {
	c := loadChecker(t)
	tests := []struct {
		name     string
		body     string
		decision rules.Decision
		ruleID   string
		reason   string
		errSub   string
	}{
		{
			name: "exactly 500.00 dollars", body: transfer("50000"),
			decision: rules.Allow, reason: rules.AllowReason,
		},
		{
			name: "one cent under 500 dollars", body: transfer("49999"),
			decision: rules.Allow, reason: rules.AllowReason,
		},
		{
			name: "one cent", body: transfer("1"),
			decision: rules.Allow, reason: rules.AllowReason,
		},
		{
			name: "500.01 dollars needs approval", body: transfer("50001"),
			decision: rules.NeedsApproval, ruleID: "transfer_over_500_needs_approval",
			reason: "transfers over $500.00 need human approval",
		},
		{
			name: "large transfer needs approval", body: transfer("200000"),
			decision: rules.NeedsApproval, ruleID: "transfer_over_500_needs_approval",
		},
		{
			name: "zero cents denied", body: transfer("0"),
			decision: rules.Deny, ruleID: "transfer_amount_must_be_positive",
			reason: "transfer amount must be a positive number of cents",
		},
		{
			name: "negative one cent denied", body: transfer("-1"),
			decision: rules.Deny, ruleID: "transfer_amount_must_be_positive",
		},
		{
			name: "negative zero denied", body: transfer("-0"),
			decision: rules.Deny, ruleID: "transfer_amount_must_be_positive",
		},
		{
			name: "negative magnitude over 500 is deny not approval", body: transfer("-50001"),
			decision: rules.Deny, ruleID: "transfer_amount_must_be_positive",
		},
		{
			name: "float 500.01", body: transfer("500.01"), errSub: "floating-point",
		},
		{
			name: "float 500.00", body: transfer("500.00"), errSub: "floating-point",
		},
		{
			name: "float 50000.0", body: transfer("50000.0"), errSub: "floating-point",
		},
		{
			name: "exponent", body: transfer("5e4"), errSub: "floating-point",
		},
		{
			name: "string amount", body: transfer(`"50000"`), errSub: "a string",
		},
		{
			name: "malformed", body: `{`, errSub: "malformed JSON",
		},
		{
			name: "empty", body: ``, errSub: "empty body",
		},
		{
			name: "trailing json", body: transfer("100") + "{}", errSub: "extra data",
		},
		{
			name: "unknown tool", body: `{"tool":"wire","arguments":{}}`, errSub: `unknown tool "wire"`,
		},
		{
			name: "unknown field", body: `{"tool":"transfer","arguments":{"from_account":"a","to_account":"b","amount":500,"currency":"USD"}}`,
			errSub: `unknown field "amount"`,
		},
		{
			name: "missing field", body: `{"tool":"transfer","arguments":{"from_account":"a","to_account":"b","currency":"USD"}}`,
			errSub: `missing field "amount_cents"`,
		},
		{
			name: "wrong type", body: `{"tool":"transfer","arguments":{"from_account":"a","to_account":"b","amount_cents":100,"currency":1}}`,
			errSub: `field "currency"`,
		},
		{
			name: "get balance", body: `{"tool":"get_balance","arguments":{"account_id":"acct_1"}}`,
			decision: rules.Allow, reason: rules.AllowReason,
		},
		{
			name: "update record", body: `{"tool":"update_record","arguments":{"record_id":"rec_1","field_name":"status","value":"closed"}}`,
			decision: rules.Allow, reason: rules.AllowReason,
		},
		{
			name: "optional memo omitted", body: transfer("100"),
			decision: rules.Allow, reason: rules.AllowReason,
		},
		{
			name:     "optional memo present",
			body:     `{"tool":"transfer","arguments":{"from_account":"a","to_account":"b","amount_cents":100,"currency":"USD","memo":"rent"}}`,
			decision: rules.Allow, reason: rules.AllowReason,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := c.Check([]byte(tc.body))
			if tc.errSub != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got %+v", tc.errSub, got)
				}
				if !strings.Contains(err.Error(), tc.errSub) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.errSub)
				}
				if got.Decision != "" {
					t.Fatalf("decision %q returned with schema error", got.Decision)
				}
				var schemaErr *schema.Error
				if !errors.As(err, &schemaErr) {
					t.Fatalf("error type %T", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Decision != tc.decision {
				t.Fatalf("decision = %s, want %s (reason %s)", got.Decision, tc.decision, got.Reason)
			}
			if tc.ruleID != "" && got.RuleID != tc.ruleID {
				t.Fatalf("rule = %s, want %s", got.RuleID, tc.ruleID)
			}
			if tc.reason != "" && got.Reason != tc.reason {
				t.Fatalf("reason = %q, want %q", got.Reason, tc.reason)
			}
			if tc.decision == rules.Allow && got.RuleID != "" {
				t.Fatalf("allow carried rule %s", got.RuleID)
			}
		})
	}
}

func TestIntegerExactPastFloat64Mantissa(t *testing.T) {
	raw := `{
	  "tools": {"transfer": {"arguments": {"amount_cents": {"type":"integer","required":true}}}},
	  "rules": [{"id":"exact","tool":"transfer","field":"amount_cents","op":"eq","value":9007199254740993,"decision":"deny","reason":"exact"}]
	}`
	policy, err := config.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	c := check.New(policy)

	got, err := c.Check([]byte(`{"tool":"transfer","arguments":{"amount_cents":9007199254740993}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got.Decision != rules.Deny || got.RuleID != "exact" {
		t.Fatalf("exact value did not match: %+v", got)
	}

	got, err = c.Check([]byte(`{"tool":"transfer","arguments":{"amount_cents":9007199254740992}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got.Decision != rules.Allow {
		t.Fatalf("neighbor matched, which is what a float64 rounding bug would do: %+v", got)
	}
}

func TestCheckConcurrent(t *testing.T) {
	c := loadChecker(t)
	body := []byte(transfer("50000"))
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := c.Check(body)
			if err != nil {
				t.Errorf("check: %v", err)
				return
			}
			if got.Decision != rules.Allow {
				t.Errorf("decision %s", got.Decision)
			}
		}()
	}
	wg.Wait()
}
