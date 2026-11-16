package rules_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/sinsuki/guardrail-proxy/internal/rules"
	"github.com/sinsuki/guardrail-proxy/internal/schema"
)

func intCall(n int64) schema.Call {
	return schema.Call{
		Tool: "transfer",
		Args: map[string]schema.Value{
			"amount_cents": {Type: schema.TypeInteger, Int: n},
		},
	}
}

func intRule(id string, op rules.Op, n int64, decision rules.Decision) rules.Rule {
	return rules.Rule{
		ID:       id,
		Tool:     "transfer",
		Field:    "amount_cents",
		Op:       op,
		Kind:     schema.TypeInteger,
		Int:      n,
		Decision: decision,
		Reason:   id,
	}
}

func TestIntegerComparisons(t *testing.T) {
	tests := []struct {
		op    rules.Op
		have  int64
		want  int64
		match bool
	}{
		{rules.OpEq, 5, 5, true},
		{rules.OpEq, 5, 6, false},
		{rules.OpNe, 5, 6, true},
		{rules.OpNe, 5, 5, false},
		{rules.OpLt, 4, 5, true},
		{rules.OpLt, 5, 5, false},
		{rules.OpLt, 6, 5, false},
		{rules.OpLte, 4, 5, true},
		{rules.OpLte, 5, 5, true},
		{rules.OpLte, 6, 5, false},
		{rules.OpGt, 6, 5, true},
		{rules.OpGt, 5, 5, false},
		{rules.OpGt, 4, 5, false},
		{rules.OpGte, 6, 5, true},
		{rules.OpGte, 5, 5, true},
		{rules.OpGte, 4, 5, false},
		{rules.OpGt, 50001, 50000, true},
		{rules.OpGt, 50000, 50000, false},
		{rules.OpLt, 0, 1, true},
		{rules.OpLt, 1, 1, false},
		{rules.OpLt, -1, 1, true},
		{rules.OpEq, 9007199254740993, 9007199254740993, true},
		{rules.OpEq, 9007199254740992, 9007199254740993, false},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s %d vs %d", tc.op, tc.have, tc.want), func(t *testing.T) {
			rule := intRule("cmp", tc.op, tc.want, rules.Deny)
			got, err := rules.Evaluate([]rules.Rule{rule}, intCall(tc.have))
			if err != nil {
				t.Fatal(err)
			}
			if tc.match {
				if got.Decision != rules.Deny || got.RuleID != "cmp" {
					t.Fatalf("got %+v", got)
				}
				return
			}
			if got.Decision != rules.Allow || got.RuleID != "" || got.Reason != rules.AllowReason {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestFirstMatchWins(t *testing.T) {
	set := []rules.Rule{
		intRule("first", rules.OpGt, 0, rules.Deny),
		intRule("second", rules.OpGt, 0, rules.NeedsApproval),
	}
	got, err := rules.Evaluate(set, intCall(10))
	if err != nil {
		t.Fatal(err)
	}
	if got.Decision != rules.Deny || got.RuleID != "first" || got.Reason != "first" {
		t.Fatalf("%+v", got)
	}
}

func TestRuleForAnotherToolDoesNotMatch(t *testing.T) {
	rule := intRule("other", rules.OpGt, 0, rules.Deny)
	rule.Tool = "wire"
	got, err := rules.Evaluate([]rules.Rule{rule}, intCall(10))
	if err != nil {
		t.Fatal(err)
	}
	if got.Decision != rules.Allow || got.Tool != "transfer" {
		t.Fatalf("%+v", got)
	}
}

func TestNoRulesAllow(t *testing.T) {
	got, err := rules.Evaluate(nil, intCall(50001))
	if err != nil {
		t.Fatal(err)
	}
	if got.Decision != rules.Allow || got.Reason != rules.AllowReason || got.RuleID != "" {
		t.Fatalf("%+v", got)
	}
}

func TestStringAndBoolRules(t *testing.T) {
	call := schema.Call{
		Tool: "transfer",
		Args: map[string]schema.Value{
			"currency": {Type: schema.TypeString, Str: "USD"},
			"expedite": {Type: schema.TypeBoolean, Bool: false},
		},
	}
	tests := []struct {
		name     string
		rule     rules.Rule
		decision rules.Decision
		ruleID   string
	}{
		{
			name:     "string eq match",
			rule:     rules.Rule{ID: "usd", Tool: "transfer", Field: "currency", Op: rules.OpEq, Kind: schema.TypeString, Str: "USD", Decision: rules.Deny, Reason: "usd"},
			decision: rules.Deny, ruleID: "usd",
		},
		{
			name:     "string eq miss",
			rule:     rules.Rule{ID: "eur", Tool: "transfer", Field: "currency", Op: rules.OpEq, Kind: schema.TypeString, Str: "EUR", Decision: rules.Deny, Reason: "eur"},
			decision: rules.Allow,
		},
		{
			name:     "string ne match",
			rule:     rules.Rule{ID: "not-eur", Tool: "transfer", Field: "currency", Op: rules.OpNe, Kind: schema.TypeString, Str: "EUR", Decision: rules.NeedsApproval, Reason: "not-eur"},
			decision: rules.NeedsApproval, ruleID: "not-eur",
		},
		{
			name:     "bool false matches eq false",
			rule:     rules.Rule{ID: "slow", Tool: "transfer", Field: "expedite", Op: rules.OpEq, Kind: schema.TypeBoolean, Bool: false, Decision: rules.Deny, Reason: "slow"},
			decision: rules.Deny, ruleID: "slow",
		},
		{
			name:     "bool false does not match eq true",
			rule:     rules.Rule{ID: "rush", Tool: "transfer", Field: "expedite", Op: rules.OpEq, Kind: schema.TypeBoolean, Bool: true, Decision: rules.Deny, Reason: "rush"},
			decision: rules.Allow,
		},
		{
			name:     "bool ne",
			rule:     rules.Rule{ID: "not-true", Tool: "transfer", Field: "expedite", Op: rules.OpNe, Kind: schema.TypeBoolean, Bool: true, Decision: rules.NeedsApproval, Reason: "not-true"},
			decision: rules.NeedsApproval, ruleID: "not-true",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := rules.Evaluate([]rules.Rule{tc.rule}, call)
			if err != nil {
				t.Fatal(err)
			}
			if got.Decision != tc.decision || got.RuleID != tc.ruleID {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestEvaluateErrors(t *testing.T) {
	tests := []struct {
		name   string
		rule   rules.Rule
		call   schema.Call
		errSub string
	}{
		{
			name:   "missing field",
			rule:   intRule("missing", rules.OpGt, 0, rules.Deny),
			call:   schema.Call{Tool: "transfer", Args: map[string]schema.Value{}},
			errSub: "not present",
		},
		{
			name: "type mismatch",
			rule: intRule("types", rules.OpGt, 0, rules.Deny),
			call: schema.Call{Tool: "transfer", Args: map[string]schema.Value{
				"amount_cents": {Type: schema.TypeString, Str: "1"},
			}},
			errSub: "type",
		},
		{
			name:   "bad integer op",
			rule:   intRule("bad-op", "approx", 1, rules.Deny),
			call:   intCall(1),
			errSub: "approx",
		},
		{
			name: "gt on a string",
			rule: rules.Rule{ID: "bad-str", Tool: "transfer", Field: "currency", Op: rules.OpGt, Kind: schema.TypeString, Str: "USD", Decision: rules.Deny, Reason: "x"},
			call: schema.Call{Tool: "transfer", Args: map[string]schema.Value{
				"currency": {Type: schema.TypeString, Str: "USD"},
			}},
			errSub: "only valid for integers",
		},
		{
			name:   "allow is not a rule decision",
			rule:   intRule("allow-rule", rules.OpGt, 0, rules.Allow),
			call:   intCall(1),
			errSub: "cannot be produced",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := rules.Evaluate([]rules.Rule{tc.rule}, tc.call)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.errSub) {
				t.Fatalf("error %q", err)
			}
		})
	}
}
