// Package config loads a policy file of tool schemas and business rules.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/sinsuki/guardrail-proxy/internal/rules"
	"github.com/sinsuki/guardrail-proxy/internal/schema"
)

// Policy is the compiled schema catalog and the ordered rule list.
type Policy struct {
	Catalog schema.Catalog
	Rules   []rules.Rule
}

type wirePolicy struct {
	Tools map[string]wireTool `json:"tools"`
	Rules []wireRule          `json:"rules"`
}

type wireTool struct {
	// Description is operator documentation in the policy file. The checker does not read it.
	Description string `json:"description"`
	// Arguments is a pointer so a missing key is an error and {} is a tool with no fields.
	Arguments *map[string]wireField `json:"arguments"`
}

type wireField struct {
	Type     string `json:"type"`
	Required *bool  `json:"required"`
}

type wireRule struct {
	ID       string          `json:"id"`
	Tool     string          `json:"tool"`
	Field    string          `json:"field"`
	Op       string          `json:"op"`
	Value    json.RawMessage `json:"value"`
	Decision string          `json:"decision"`
	Reason   string          `json:"reason"`
}

// Load reads a policy from path.
func Load(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("read policy: %w", err)
	}
	policy, err := Parse(data)
	if err != nil {
		return Policy{}, fmt.Errorf("parse policy %s: %w", path, err)
	}
	return policy, nil
}

// Parse compiles a policy from JSON.
// Unknown fields are rejected. Rule values use the same literal parser as tool arguments.
func Parse(data []byte) (Policy, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return Policy{}, errors.New("policy is empty")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var wire wirePolicy
	if err := dec.Decode(&wire); err != nil {
		return Policy{}, fmt.Errorf("policy JSON: %w", err)
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); err != io.EOF {
		return Policy{}, errors.New("policy JSON: extra data after the object")
	}
	return build(wire)
}

func build(wire wirePolicy) (Policy, error) {
	if wire.Tools == nil {
		return Policy{}, errors.New("policy: missing \"tools\"")
	}
	cat := schema.Catalog{Tools: make(map[string]schema.Tool, len(wire.Tools))}
	for name, tool := range wire.Tools {
		if name == "" {
			return Policy{}, errors.New("policy: tool name is empty")
		}
		if tool.Arguments == nil {
			return Policy{}, fmt.Errorf("policy: tool %q is missing \"arguments\"", name)
		}
		fields := make(map[string]schema.Field, len(*tool.Arguments))
		for fname, field := range *tool.Arguments {
			if fname == "" {
				return Policy{}, fmt.Errorf("policy: tool %q has an empty field name", name)
			}
			kind := schema.FieldType(field.Type)
			if !kind.Valid() {
				return Policy{}, fmt.Errorf("policy: tool %q field %q: type %q is not supported (use \"string\", \"integer\", or \"boolean\")", name, fname, field.Type)
			}
			if field.Required == nil {
				return Policy{}, fmt.Errorf("policy: tool %q field %q: \"required\" must be true or false", name, fname)
			}
			fields[fname] = schema.Field{Type: kind, Required: *field.Required}
		}
		cat.Tools[name] = schema.Tool{Fields: fields}
	}

	seen := make(map[string]struct{}, len(wire.Rules))
	compiled := make([]rules.Rule, 0, len(wire.Rules))
	for _, raw := range wire.Rules {
		rule, err := compileRule(cat, raw)
		if err != nil {
			return Policy{}, err
		}
		if _, ok := seen[rule.ID]; ok {
			return Policy{}, fmt.Errorf("policy: duplicate rule id %q", rule.ID)
		}
		seen[rule.ID] = struct{}{}
		compiled = append(compiled, rule)
	}
	return Policy{Catalog: cat, Rules: compiled}, nil
}

func compileRule(cat schema.Catalog, raw wireRule) (rules.Rule, error) {
	if raw.ID == "" {
		return rules.Rule{}, errors.New("policy: a rule is missing \"id\"")
	}
	if raw.Reason == "" {
		return rules.Rule{}, fmt.Errorf("policy: rule %q is missing \"reason\"", raw.ID)
	}
	if raw.Tool == "" {
		return rules.Rule{}, fmt.Errorf("policy: rule %q is missing \"tool\"", raw.ID)
	}
	tool, ok := cat.Tools[raw.Tool]
	if !ok {
		return rules.Rule{}, fmt.Errorf("policy: rule %q: unknown tool %q", raw.ID, raw.Tool)
	}
	if raw.Field == "" {
		return rules.Rule{}, fmt.Errorf("policy: rule %q is missing \"field\"", raw.ID)
	}
	field, ok := tool.Fields[raw.Field]
	if !ok {
		return rules.Rule{}, fmt.Errorf("policy: rule %q: unknown field %q on tool %q", raw.ID, raw.Field, raw.Tool)
	}
	if !field.Required {
		return rules.Rule{}, fmt.Errorf("policy: rule %q: field %q is optional; rules only apply to required fields", raw.ID, raw.Field)
	}
	op := rules.Op(raw.Op)
	if !opAllowed(field.Type, op) {
		return rules.Rule{}, fmt.Errorf("policy: rule %q: op %q is not valid for %s", raw.ID, raw.Op, field.Type)
	}
	decision := rules.Decision(raw.Decision)
	if decision != rules.Deny && decision != rules.NeedsApproval {
		return rules.Rule{}, fmt.Errorf("policy: rule %q: decision must be \"deny\" or \"needs_approval\"", raw.ID)
	}
	if len(bytes.TrimSpace(raw.Value)) == 0 {
		return rules.Rule{}, fmt.Errorf("policy: rule %q is missing \"value\"", raw.ID)
	}
	val, err := schema.ParseLiteral(field.Type, raw.Value)
	if err != nil {
		return rules.Rule{}, fmt.Errorf("policy: rule %q: value: %w", raw.ID, err)
	}
	return rules.Rule{
		ID:       raw.ID,
		Tool:     raw.Tool,
		Field:    raw.Field,
		Op:       op,
		Kind:     field.Type,
		Int:      val.Int,
		Str:      val.Str,
		Bool:     val.Bool,
		Decision: decision,
		Reason:   raw.Reason,
	}, nil
}

func opAllowed(kind schema.FieldType, op rules.Op) bool {
	switch kind {
	case schema.TypeInteger:
		switch op {
		case rules.OpEq, rules.OpNe, rules.OpLt, rules.OpLte, rules.OpGt, rules.OpGte:
			return true
		}
	case schema.TypeString, schema.TypeBoolean:
		switch op {
		case rules.OpEq, rules.OpNe:
			return true
		}
	}
	return false
}
