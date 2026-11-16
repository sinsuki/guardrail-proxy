// Package rules evaluates business rules against a validated tool call.
// Rules run in the order they are given. The first match wins. If none match,
// the decision is allow.
package rules

import (
	"fmt"

	"github.com/sinsuki/guardrail-proxy/internal/schema"
)

// Decision is the rule engine's answer for one call.
type Decision string

const (
	Allow         Decision = "allow"
	Deny          Decision = "deny"
	NeedsApproval Decision = "needs_approval"
)

// AllowReason is the reason used when no rule matches.
const AllowReason = "allowed"

// Op is a comparison against one field.
type Op string

const (
	OpEq  Op = "eq"
	OpNe  Op = "ne"
	OpLt  Op = "lt"
	OpLte Op = "lte"
	OpGt  Op = "gt"
	OpGte Op = "gte"
)

// Rule is one compiled business rule. Kind selects which value is compared.
type Rule struct {
	ID       string
	Tool     string
	Field    string
	Op       Op
	Kind     schema.FieldType
	Int      int64
	Str      string
	Bool     bool
	Decision Decision
	Reason   string
}

// Result is the decision for one call, including the winning rule when one matched.
type Result struct {
	Tool     string
	Decision Decision
	Reason   string
	RuleID   string
}

// Evaluate runs rules in order against call.
// An error means a rule is inconsistent with the call, which the policy loader
// is expected to prevent. It is not a business denial.
func Evaluate(ruleSet []Rule, call schema.Call) (Result, error) {
	for _, rule := range ruleSet {
		if rule.Tool != call.Tool {
			continue
		}
		val, ok := call.Args[rule.Field]
		if !ok {
			return Result{}, fmt.Errorf("rule %q: field %q not present", rule.ID, rule.Field)
		}
		if val.Type != rule.Kind {
			return Result{}, fmt.Errorf("rule %q: field %q has type %s, rule expects %s", rule.ID, rule.Field, val.Type, rule.Kind)
		}
		matched, err := compare(rule, val)
		if err != nil {
			return Result{}, fmt.Errorf("rule %q: %w", rule.ID, err)
		}
		if !matched {
			continue
		}
		if rule.Decision != Deny && rule.Decision != NeedsApproval {
			return Result{}, fmt.Errorf("rule %q: decision %q cannot be produced by a rule", rule.ID, rule.Decision)
		}
		return Result{
			Tool:     call.Tool,
			Decision: rule.Decision,
			Reason:   rule.Reason,
			RuleID:   rule.ID,
		}, nil
	}
	return Result{Tool: call.Tool, Decision: Allow, Reason: AllowReason}, nil
}

func compare(rule Rule, val schema.Value) (bool, error) {
	switch rule.Kind {
	case schema.TypeInteger:
		return cmpInt(rule.Op, val.Int, rule.Int)
	case schema.TypeString:
		return cmpEquality(rule.Op, val.Str == rule.Str)
	case schema.TypeBoolean:
		return cmpEquality(rule.Op, val.Bool == rule.Bool)
	default:
		return false, fmt.Errorf("unsupported type %q", rule.Kind)
	}
}

func cmpInt(op Op, got, want int64) (bool, error) {
	switch op {
	case OpEq:
		return got == want, nil
	case OpNe:
		return got != want, nil
	case OpLt:
		return got < want, nil
	case OpLte:
		return got <= want, nil
	case OpGt:
		return got > want, nil
	case OpGte:
		return got >= want, nil
	default:
		return false, fmt.Errorf("op %q is not valid for an integer", op)
	}
}

func cmpEquality(op Op, equal bool) (bool, error) {
	switch op {
	case OpEq:
		return equal, nil
	case OpNe:
		return !equal, nil
	default:
		return false, fmt.Errorf("op %q is only valid for integers", op)
	}
}
