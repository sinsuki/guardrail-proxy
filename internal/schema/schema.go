// Package schema checks an agent tool call against a per-tool argument schema.
// Unknown tools, unknown fields, missing fields, duplicate fields, and wrong
// types are rejected. Integer fields are read from the JSON literal, not via
// float64, so money in cents cannot be rounded or smuggled in as a float.
package schema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
)

// FieldType is the JSON type a tool argument must have.
type FieldType string

const (
	TypeString  FieldType = "string"
	TypeInteger FieldType = "integer"
	TypeBoolean FieldType = "boolean"
)

// Valid reports whether t is one of the supported field types.
func (t FieldType) Valid() bool {
	switch t {
	case TypeString, TypeInteger, TypeBoolean:
		return true
	default:
		return false
	}
}

// Field is one argument of a tool.
type Field struct {
	Type     FieldType
	Required bool
}

// Tool is the set of arguments a single tool accepts.
type Tool struct {
	Fields map[string]Field
}

// Catalog is the set of tools an agent is allowed to call.
type Catalog struct {
	Tools map[string]Tool
}

// Value is a parsed argument. Only the field matching Type is set.
type Value struct {
	Type FieldType
	Int  int64
	Str  string
	Bool bool
}

// Call is a tool call that has passed schema validation.
type Call struct {
	Tool string
	Args map[string]Value
}

// Error is a rejected tool call. The proxy maps it to HTTP 400.
type Error struct {
	Message string
}

func (e *Error) Error() string { return e.Message }

// Validate parses body and checks it against cat.
// On success the returned call holds typed arguments.
func Validate(cat Catalog, body []byte) (Call, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return Call{}, &Error{Message: "request is malformed JSON: empty body"}
	}

	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	top, err := decodeStrictObject(dec, "request")
	if err != nil {
		return Call{}, err
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); err != io.EOF {
		return Call{}, &Error{Message: "request is malformed JSON: extra data after the object"}
	}

	var unknownTop []string
	for name := range top {
		if name != "tool" && name != "arguments" {
			unknownTop = append(unknownTop, name)
		}
	}
	if len(unknownTop) > 0 {
		sort.Strings(unknownTop)
		return Call{}, &Error{Message: fmt.Sprintf("unknown field %q in request", unknownTop[0])}
	}

	toolRaw, ok := top["tool"]
	if !ok {
		return Call{}, &Error{Message: "missing field \"tool\""}
	}
	toolVal, err := ParseLiteral(TypeString, toolRaw)
	if err != nil {
		return Call{}, &Error{Message: "field \"tool\": " + err.Error()}
	}
	argsRaw, ok := top["arguments"]
	if !ok {
		return Call{}, &Error{Message: "missing field \"arguments\""}
	}

	argsDec := json.NewDecoder(bytes.NewReader(argsRaw))
	argsDec.UseNumber()
	args, err := decodeStrictObject(argsDec, "arguments")
	if err != nil {
		return Call{}, err
	}
	var argsTrailing json.RawMessage
	if err := argsDec.Decode(&argsTrailing); err != io.EOF {
		return Call{}, &Error{Message: "arguments is malformed JSON: extra data after the object"}
	}

	tool, known := cat.Tools[toolVal.Str]
	if !known {
		return Call{}, &Error{Message: fmt.Sprintf("unknown tool %q", toolVal.Str)}
	}
	if tool.Fields == nil {
		tool.Fields = map[string]Field{}
	}

	var unknown []string
	for name := range args {
		if _, ok := tool.Fields[name]; !ok {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return Call{}, &Error{Message: fmt.Sprintf("unknown field %q on tool %q", unknown[0], toolVal.Str)}
	}

	var missing []string
	for name, field := range tool.Fields {
		if field.Required {
			if _, ok := args[name]; !ok {
				missing = append(missing, name)
			}
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return Call{}, &Error{Message: fmt.Sprintf("missing field %q on tool %q", missing[0], toolVal.Str)}
	}

	parsed := make(map[string]Value, len(args))
	var typeErrs []string
	for name, raw := range args {
		field := tool.Fields[name]
		val, err := ParseLiteral(field.Type, raw)
		if err != nil {
			typeErrs = append(typeErrs, fmt.Sprintf("field %q on tool %q: %s", name, toolVal.Str, err.Error()))
			continue
		}
		parsed[name] = val
	}
	if len(typeErrs) > 0 {
		sort.Strings(typeErrs)
		return Call{}, &Error{Message: typeErrs[0]}
	}

	return Call{Tool: toolVal.Str, Args: parsed}, nil
}

// ParseLiteral parses one JSON literal that must be kind.
// Integers must be canonical base-10 literals with no fraction and no exponent.
func ParseLiteral(kind FieldType, raw json.RawMessage) (Value, error) {
	raw = bytes.TrimSpace(raw)
	switch kind {
	case TypeString:
		return parseString(raw)
	case TypeBoolean:
		return parseBoolean(raw)
	case TypeInteger:
		return parseInteger(raw)
	default:
		return Value{}, fmt.Errorf("unknown type %q", kind)
	}
}

func parseString(raw []byte) (Value, error) {
	if len(raw) == 0 || raw[0] != '"' {
		return Value{}, fmt.Errorf("expected a string, got %s", jsonKind(raw))
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return Value{}, fmt.Errorf("expected a string, got malformed JSON")
	}
	return Value{Type: TypeString, Str: s}, nil
}

func parseBoolean(raw []byte) (Value, error) {
	switch string(raw) {
	case "true":
		return Value{Type: TypeBoolean, Bool: true}, nil
	case "false":
		return Value{Type: TypeBoolean, Bool: false}, nil
	default:
		return Value{}, fmt.Errorf("expected a boolean, got %s", jsonKind(raw))
	}
}

func parseInteger(raw []byte) (Value, error) {
	if len(raw) == 0 || !looksLikeNumber(raw) {
		return Value{}, fmt.Errorf("expected an integer, got %s", jsonKind(raw))
	}
	// Reject before ParseInt so 500.00 and 1e2 cannot become whole numbers.
	if isFloating(raw) {
		return Value{}, fmt.Errorf("expected an integer, got a floating-point number")
	}
	if !canonicalInteger(raw) {
		return Value{}, fmt.Errorf("expected an integer, got a non-canonical number")
	}
	n, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil {
		return Value{}, fmt.Errorf("expected an integer in the int64 range")
	}
	return Value{Type: TypeInteger, Int: n}, nil
}

func looksLikeNumber(raw []byte) bool {
	return raw[0] == '-' || (raw[0] >= '0' && raw[0] <= '9')
}

func isFloating(raw []byte) bool {
	return bytes.ContainsAny(raw, ".eE")
}

// canonicalInteger accepts 0, -0, and non-zero integers without leading zeros.
func canonicalInteger(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}
	i := 0
	if raw[0] == '-' {
		if len(raw) == 1 {
			return false
		}
		i = 1
	}
	if raw[i] == '0' {
		return len(raw) == i+1
	}
	if raw[i] < '1' || raw[i] > '9' {
		return false
	}
	for _, c := range raw[i+1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func jsonKind(raw []byte) string {
	switch {
	case len(raw) == 0:
		return "an empty value"
	case bytes.Equal(raw, []byte("true")), bytes.Equal(raw, []byte("false")):
		return "a boolean"
	case bytes.Equal(raw, []byte("null")):
		return "null"
	case raw[0] == '"':
		return "a string"
	case raw[0] == '{':
		return "an object"
	case raw[0] == '[':
		return "an array"
	case looksLikeNumber(raw):
		return "a number"
	default:
		return "a non-JSON value"
	}
}

// decodeStrictObject reads one JSON object and rejects duplicate keys.
// where is "request" or "arguments" and is used in error text.
func decodeStrictObject(dec *json.Decoder, where string) (map[string]json.RawMessage, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, malformed(where, err)
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return nil, &Error{Message: where + " must be a JSON object"}
	}

	fields := make(map[string]json.RawMessage)
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, malformed(where, err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, malformed(where, fmt.Errorf("object key is not a string"))
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, malformed(where, err)
		}
		if _, exists := fields[key]; exists {
			return nil, &Error{Message: fmt.Sprintf("duplicate field %q in %s", key, where)}
		}
		fields[key] = bytes.TrimSpace(raw)
	}

	tok, err = dec.Token()
	if err != nil {
		return nil, malformed(where, err)
	}
	end, ok := tok.(json.Delim)
	if !ok || end != '}' {
		return nil, malformed(where, fmt.Errorf("object did not end"))
	}
	return fields, nil
}

func malformed(where string, err error) error {
	if where == "request" {
		return &Error{Message: "request is malformed JSON: " + err.Error()}
	}
	return &Error{Message: "arguments are malformed JSON: " + err.Error()}
}
