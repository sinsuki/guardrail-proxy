package config_test

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

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

func TestLoadSamplePolicy(t *testing.T) {
	policy, err := config.Load(policyPath(t))
	if err != nil {
		t.Fatal(err)
	}

	transfer, ok := policy.Catalog.Tools["transfer"]
	if !ok {
		t.Fatal("missing transfer")
	}
	amount := transfer.Fields["amount_cents"]
	if amount.Type != schema.TypeInteger || !amount.Required {
		t.Fatalf("amount_cents %+v", amount)
	}
	memo := transfer.Fields["memo"]
	if memo.Type != schema.TypeString || memo.Required {
		t.Fatalf("memo %+v", memo)
	}
	for _, name := range []string{"from_account", "to_account", "currency"} {
		field := transfer.Fields[name]
		if field.Type != schema.TypeString || !field.Required {
			t.Fatalf("%s %+v", name, field)
		}
	}
	if _, ok := policy.Catalog.Tools["get_balance"]; !ok {
		t.Fatal("missing get_balance")
	}
	if _, ok := policy.Catalog.Tools["update_record"]; !ok {
		t.Fatal("missing update_record")
	}
	if policy.Catalog.Tools["get_balance"].Fields["account_id"].Type != schema.TypeString {
		t.Fatal("account_id")
	}

	if len(policy.Rules) != 2 {
		t.Fatalf("rules = %d", len(policy.Rules))
	}
	positive := policy.Rules[0]
	if positive.ID != "transfer_amount_must_be_positive" || positive.Op != rules.OpLt || positive.Int != 1 || positive.Decision != rules.Deny {
		t.Fatalf("%+v", positive)
	}
	if positive.Reason != "transfer amount must be a positive number of cents" {
		t.Fatal(positive.Reason)
	}
	over := policy.Rules[1]
	if over.ID != "transfer_over_500_needs_approval" || over.Op != rules.OpGt || over.Int != 50000 || over.Decision != rules.NeedsApproval {
		t.Fatalf("%+v", over)
	}
	if over.Reason != "transfers over $500.00 need human approval" {
		t.Fatal(over.Reason)
	}
}

func TestParseCompilesTypedValues(t *testing.T) {
	raw := `{
	  "tools": {
	    "transfer": {
	      "description": "docs only",
	      "arguments": {
	        "amount_cents": {"type": "integer", "required": true},
	        "currency": {"type": "string", "required": true},
	        "expedite": {"type": "boolean", "required": true}
	      }
	    }
	  },
	  "rules": [
	    {"id": "cents", "tool": "transfer", "field": "amount_cents", "op": "gt", "value": 50000, "decision": "needs_approval", "reason": "over"},
	    {"id": "cur", "tool": "transfer", "field": "currency", "op": "eq", "value": "USD", "decision": "deny", "reason": "usd"},
	    {"id": "rush", "tool": "transfer", "field": "expedite", "op": "eq", "value": true, "decision": "deny", "reason": "rush"},
	    {"id": "slow", "tool": "transfer", "field": "expedite", "op": "eq", "value": false, "decision": "needs_approval", "reason": "slow"}
	  ]
	}`
	policy, err := config.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Rules) != 4 {
		t.Fatalf("%d rules", len(policy.Rules))
	}
	if policy.Rules[0].Int != 50000 || policy.Rules[0].Decision != rules.NeedsApproval {
		t.Fatalf("%+v", policy.Rules[0])
	}
	if policy.Rules[1].Str != "USD" || policy.Rules[1].Kind != schema.TypeString {
		t.Fatalf("%+v", policy.Rules[1])
	}
	if !policy.Rules[2].Bool || policy.Rules[2].Kind != schema.TypeBoolean {
		t.Fatalf("%+v", policy.Rules[2])
	}
	if policy.Rules[3].Bool || policy.Rules[3].Decision != rules.NeedsApproval {
		t.Fatalf("false bool was not preserved: %+v", policy.Rules[3])
	}
}

func TestParseAllowsToolWithNoArguments(t *testing.T) {
	policy, err := config.Parse([]byte(`{"tools":{"ping":{"arguments":{}}},"rules":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	tool, ok := policy.Catalog.Tools["ping"]
	if !ok {
		t.Fatal("missing ping")
	}
	if len(tool.Fields) != 0 {
		t.Fatalf("fields = %d", len(tool.Fields))
	}
}

func TestParseRejects(t *testing.T) {
	const tools = `"tools":{"transfer":{"arguments":{"amount_cents":{"type":"integer","required":true},"currency":{"type":"string","required":true},"note":{"type":"string","required":false},"expedite":{"type":"boolean","required":true}}}}`

	rule := func(body string) string {
		return "{" + tools + `,"rules":[` + body + `]}`
	}

	tests := []struct {
		name   string
		body   string
		errSub string
	}{
		{name: "empty", body: ``, errSub: "empty"},
		{name: "whitespace", body: " \n", errSub: "empty"},
		{name: "array", body: `[]`, errSub: "policy JSON"},
		{name: "trailing", body: `{"tools":{},"rules":[]}{}`, errSub: "extra data"},
		{name: "unknown top level", body: `{"tools":{},"rules":[],"extra":1}`, errSub: "unknown field"},
		{name: "missing tools", body: `{"rules":[]}`, errSub: `missing "tools"`},
		{name: "null tools", body: `{"tools":null,"rules":[]}`, errSub: `missing "tools"`},
		{name: "empty tool name", body: `{"tools":{"":{"arguments":{}}},"rules":[]}`, errSub: "tool name is empty"},
		{name: "missing arguments", body: `{"tools":{"transfer":{"description":"x"}},"rules":[]}`, errSub: `missing "arguments"`},
		{name: "null arguments", body: `{"tools":{"transfer":{"arguments":null}},"rules":[]}`, errSub: `missing "arguments"`},
		{name: "type number", body: `{"tools":{"transfer":{"arguments":{"amount_cents":{"type":"number","required":true}}}},"rules":[]}`, errSub: "not supported"},
		{name: "required omitted", body: `{"tools":{"transfer":{"arguments":{"amount_cents":{"type":"integer"}}}},"rules":[]}`, errSub: `"required"`},
		{name: "empty field name", body: `{"tools":{"transfer":{"arguments":{"":{"type":"string","required":true}}}},"rules":[]}`, errSub: "empty field name"},
		{name: "unknown tool field", body: `{"tools":{"transfer":{"arguments":{"amount_cents":{"type":"integer","required":true,"min":0}}}},"rules":[]}`, errSub: "unknown field"},
		{name: "misspelled description", body: `{"tools":{"transfer":{"desc":"x","arguments":{}}},"rules":[]}`, errSub: "unknown field"},
		{name: "missing id", body: rule(`{"tool":"transfer","field":"amount_cents","op":"gt","value":1,"decision":"deny","reason":"x"}`), errSub: `missing "id"`},
		{name: "missing reason", body: rule(`{"id":"r","tool":"transfer","field":"amount_cents","op":"gt","value":1,"decision":"deny"}`), errSub: `missing "reason"`},
		{name: "missing tool", body: rule(`{"id":"r","field":"amount_cents","op":"gt","value":1,"decision":"deny","reason":"x"}`), errSub: `missing "tool"`},
		{name: "unknown tool", body: rule(`{"id":"r","tool":"wire","field":"amount_cents","op":"gt","value":1,"decision":"deny","reason":"x"}`), errSub: `unknown tool "wire"`},
		{name: "missing field", body: rule(`{"id":"r","tool":"transfer","op":"gt","value":1,"decision":"deny","reason":"x"}`), errSub: `missing "field"`},
		{name: "unknown field", body: rule(`{"id":"r","tool":"transfer","field":"amount","op":"gt","value":1,"decision":"deny","reason":"x"}`), errSub: `unknown field "amount"`},
		{name: "optional field", body: rule(`{"id":"r","tool":"transfer","field":"note","op":"eq","value":"x","decision":"deny","reason":"x"}`), errSub: "optional"},
		{name: "bad op", body: rule(`{"id":"r","tool":"transfer","field":"amount_cents","op":"approx","value":1,"decision":"deny","reason":"x"}`), errSub: "not valid"},
		{name: "op case", body: rule(`{"id":"r","tool":"transfer","field":"amount_cents","op":"GT","value":1,"decision":"deny","reason":"x"}`), errSub: "not valid"},
		{name: "gt on string", body: rule(`{"id":"r","tool":"transfer","field":"currency","op":"gt","value":"USD","decision":"deny","reason":"x"}`), errSub: "not valid"},
		{name: "gt on bool", body: rule(`{"id":"r","tool":"transfer","field":"expedite","op":"gt","value":true,"decision":"deny","reason":"x"}`), errSub: "not valid"},
		{name: "decision allow", body: rule(`{"id":"r","tool":"transfer","field":"amount_cents","op":"gt","value":1,"decision":"allow","reason":"x"}`), errSub: "decision must be"},
		{name: "missing decision", body: rule(`{"id":"r","tool":"transfer","field":"amount_cents","op":"gt","value":1,"reason":"x"}`), errSub: "decision must be"},
		{name: "duplicate id", body: rule(`{"id":"r","tool":"transfer","field":"amount_cents","op":"gt","value":1,"decision":"deny","reason":"x"},{"id":"r","tool":"transfer","field":"amount_cents","op":"lt","value":0,"decision":"deny","reason":"y"}`), errSub: `duplicate rule id "r"`},
		{name: "float threshold", body: rule(`{"id":"r","tool":"transfer","field":"amount_cents","op":"gt","value":1.5,"decision":"deny","reason":"x"}`), errSub: "floating-point"},
		{name: "float whole threshold", body: rule(`{"id":"r","tool":"transfer","field":"amount_cents","op":"gt","value":50000.0,"decision":"deny","reason":"x"}`), errSub: "floating-point"},
		{name: "string threshold", body: rule(`{"id":"r","tool":"transfer","field":"amount_cents","op":"gt","value":"50000","decision":"deny","reason":"x"}`), errSub: "a string"},
		{name: "null threshold", body: rule(`{"id":"r","tool":"transfer","field":"amount_cents","op":"gt","value":null,"decision":"deny","reason":"x"}`), errSub: "null"},
		{name: "missing value", body: rule(`{"id":"r","tool":"transfer","field":"amount_cents","op":"gt","decision":"deny","reason":"x"}`), errSub: `missing "value"`},
		{name: "unknown rule field", body: rule(`{"id":"r","tool":"transfer","field":"amount_cents","op":"gt","value":1,"decision":"deny","reason":"x","note":"no"}`), errSub: "unknown field"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := config.Parse([]byte(tc.body))
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.errSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.errSub)
			}
		})
	}
}
