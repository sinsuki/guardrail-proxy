// Package check runs schema validation and then the rule engine on one tool call.
package check

import (
	"github.com/sinsuki/guardrail-proxy/internal/config"
	"github.com/sinsuki/guardrail-proxy/internal/rules"
	"github.com/sinsuki/guardrail-proxy/internal/schema"
)

// Checker is a loaded policy. It is safe for concurrent use as long as the
// policy maps and rule slice are not modified after New.
type Checker struct {
	policy config.Policy
}

// New returns a checker for policy.
func New(policy config.Policy) *Checker {
	return &Checker{policy: policy}
}

// Check parses body, validates it, and evaluates the rules.
// A schema or JSON failure is returned as an error, not as a deny decision,
// so a malformed call is not confused with a business rule.
func (c *Checker) Check(body []byte) (rules.Result, error) {
	call, err := schema.Validate(c.policy.Catalog, body)
	if err != nil {
		return rules.Result{}, err
	}
	return rules.Evaluate(c.policy.Rules, call)
}
