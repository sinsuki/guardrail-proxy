package schema_test

import (
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/sinsuki/guardrail-proxy/internal/schema"
)

func catalog() schema.Catalog {
	return schema.Catalog{Tools: map[string]schema.Tool{
		"transfer": {Fields: map[string]schema.Field{
			"from_account": {Type: schema.TypeString, Required: true},
			"to_account":   {Type: schema.TypeString, Required: true},
			"amount_cents": {Type: schema.TypeInteger, Required: true},
			"currency":     {Type: schema.TypeString, Required: true},
			"memo":         {Type: schema.TypeString, Required: false},
			"expedite":     {Type: schema.TypeBoolean, Required: false},
		}},
		"ping": {Fields: map[string]schema.Field{}},
	}}
}

func transfer(amount string) string {
	return `{"tool":"transfer","arguments":{"from_account":"acct_1","to_account":"acct_2","amount_cents":` + amount + `,"currency":"USD"}}`
}

func TestParseLiteral(t *testing.T) {
	tests := []struct {
		name   string
		kind   schema.FieldType
		raw    string
		want   int64
		errSub string
	}{
		{name: "zero", kind: schema.TypeInteger, raw: "0", want: 0},
		{name: "negative zero", kind: schema.TypeInteger, raw: "-0", want: 0},
		{name: "cents", kind: schema.TypeInteger, raw: "50000", want: 50000},
		{name: "one past five hundred dollars", kind: schema.TypeInteger, raw: "50001", want: 50001},
		{name: "negative", kind: schema.TypeInteger, raw: "-1", want: -1},
		{name: "max int64", kind: schema.TypeInteger, raw: strconv.FormatInt(math.MaxInt64, 10), want: math.MaxInt64},
		{name: "min int64", kind: schema.TypeInteger, raw: strconv.FormatInt(math.MinInt64, 10), want: math.MinInt64},
		{name: "past float64 mantissa", kind: schema.TypeInteger, raw: "9007199254740993", want: 9007199254740993},
		{name: "fractional 500.00", kind: schema.TypeInteger, raw: "500.00", errSub: "floating-point"},
		{name: "fractional 500.01", kind: schema.TypeInteger, raw: "500.01", errSub: "floating-point"},
		{name: "trailing zero fraction", kind: schema.TypeInteger, raw: "50000.0", errSub: "floating-point"},
		{name: "exponent", kind: schema.TypeInteger, raw: "1e2", errSub: "floating-point"},
		{name: "exponent upper", kind: schema.TypeInteger, raw: "5E4", errSub: "floating-point"},
		{name: "leading zero", kind: schema.TypeInteger, raw: "01", errSub: "non-canonical"},
		{name: "negative leading zero", kind: schema.TypeInteger, raw: "-01", errSub: "non-canonical"},
		{name: "plus sign", kind: schema.TypeInteger, raw: "+10", errSub: "expected an integer"},
		{name: "string digits", kind: schema.TypeInteger, raw: `"50000"`, errSub: "a string"},
		{name: "bool", kind: schema.TypeInteger, raw: "true", errSub: "a boolean"},
		{name: "null", kind: schema.TypeInteger, raw: "null", errSub: "null"},
		{name: "overflow", kind: schema.TypeInteger, raw: "9223372036854775808", errSub: "int64"},
		{name: "negative overflow", kind: schema.TypeInteger, raw: "-9223372036854775809", errSub: "int64"},
		{name: "bool true", kind: schema.TypeBoolean, raw: "true"},
		{name: "bool false", kind: schema.TypeBoolean, raw: "false"},
		{name: "bool string", kind: schema.TypeBoolean, raw: `"true"`, errSub: "a string"},
		{name: "string", kind: schema.TypeString, raw: `"USD"`},
		{name: "string from number", kind: schema.TypeString, raw: "1", errSub: "a number"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := schema.ParseLiteral(tc.kind, []byte(tc.raw))
			if tc.errSub != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got %+v", tc.errSub, got)
				}
				if !strings.Contains(err.Error(), tc.errSub) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.errSub)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.kind == schema.TypeInteger && got.Int != tc.want {
				t.Fatalf("int = %d, want %d", got.Int, tc.want)
			}
			if tc.kind == schema.TypeBoolean && tc.raw == "false" && got.Bool {
				t.Fatal("false parsed as true")
			}
			if tc.kind == schema.TypeBoolean && tc.raw == "true" && !got.Bool {
				t.Fatal("true parsed as false")
			}
			if tc.kind == schema.TypeString && got.Str != "USD" {
				t.Fatalf("str = %q", got.Str)
			}
		})
	}
}

func TestValidateRejects(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		errSub string
	}{
		{name: "empty", body: ``, errSub: "empty body"},
		{name: "whitespace", body: " \n\t", errSub: "empty body"},
		{name: "truncated", body: `{"tool":`, errSub: "malformed JSON"},
		{name: "array", body: `[]`, errSub: "must be a JSON object"},
		{name: "null", body: `null`, errSub: "must be a JSON object"},
		{name: "string", body: `"transfer"`, errSub: "must be a JSON object"},
		{name: "trailing object", body: transfer("100") + `{"tool":"ping","arguments":{}}`, errSub: "extra data"},
		{name: "missing tool", body: `{"arguments":{}}`, errSub: `missing field "tool"`},
		{name: "tool not a string", body: `{"tool":1,"arguments":{}}`, errSub: `field "tool"`},
		{name: "missing arguments", body: `{"tool":"ping"}`, errSub: `missing field "arguments"`},
		{name: "arguments null", body: `{"tool":"ping","arguments":null}`, errSub: "arguments must be a JSON object"},
		{name: "arguments array", body: `{"tool":"ping","arguments":[]}`, errSub: "arguments must be a JSON object"},
		{name: "arguments string", body: `{"tool":"ping","arguments":"x"}`, errSub: "arguments must be a JSON object"},
		{name: "unknown tool", body: `{"tool":"wire","arguments":{}}`, errSub: `unknown tool "wire"`},
		{name: "empty tool name", body: `{"tool":"","arguments":{}}`, errSub: `unknown tool ""`},
		{name: "unknown field amount", body: `{"tool":"transfer","arguments":{"from_account":"a","to_account":"b","amount":50000,"currency":"USD"}}`, errSub: `unknown field "amount"`},
		{name: "unknown field sorts first", body: `{"tool":"transfer","arguments":{"from_account":"a","to_account":"b","amount_cents":1,"currency":"USD","zzz":1,"aaa":1}}`, errSub: `unknown field "aaa"`},
		{name: "unknown before missing", body: `{"tool":"transfer","arguments":{"from_account":"a","to_account":"b","currency":"USD","zzz":1}}`, errSub: `unknown field "zzz"`},
		{name: "missing amount", body: `{"tool":"transfer","arguments":{"from_account":"a","to_account":"b","currency":"USD"}}`, errSub: `missing field "amount_cents"`},
		{name: "missing sorts first", body: `{"tool":"transfer","arguments":{"to_account":"b","amount_cents":1}}`, errSub: `missing field "currency"`},
		{name: "missing before wrong type", body: `{"tool":"transfer","arguments":{"from_account":"a","to_account":"b","amount_cents":"1"}}`, errSub: `missing field "currency"`},
		{name: "float 500.00", body: transfer("500.00"), errSub: "floating-point"},
		{name: "float 500.01", body: transfer("500.01"), errSub: "floating-point"},
		{name: "float whole with fraction", body: transfer("50000.0"), errSub: "floating-point"},
		{name: "exponent", body: transfer("1e2"), errSub: "floating-point"},
		{name: "string amount", body: transfer(`"50000"`), errSub: "got a string"},
		{name: "bool amount", body: transfer("true"), errSub: "got a boolean"},
		{name: "null amount", body: transfer("null"), errSub: "got null"},
		{name: "object amount", body: transfer(`{"cents":1}`), errSub: "got an object"},
		{name: "array amount", body: transfer("[1]"), errSub: "got an array"},
		{name: "overflow", body: transfer("9223372036854775808"), errSub: "int64"},
		{name: "leading zero", body: transfer("01"), errSub: "malformed JSON"},
		{name: "currency number", body: `{"tool":"transfer","arguments":{"from_account":"a","to_account":"b","amount_cents":1,"currency":1}}`, errSub: `field "currency"`},
		{name: "two wrong types report amount first", body: `{"tool":"transfer","arguments":{"from_account":"a","to_account":"b","amount_cents":"1","currency":1}}`, errSub: `field "amount_cents"`},
		{name: "memo wrong type", body: `{"tool":"transfer","arguments":{"from_account":"a","to_account":"b","amount_cents":1,"currency":"USD","memo":1}}`, errSub: `field "memo"`},
		{name: "expedite string", body: `{"tool":"transfer","arguments":{"from_account":"a","to_account":"b","amount_cents":1,"currency":"USD","expedite":"true"}}`, errSub: `field "expedite"`},
		{name: "duplicate argument", body: `{"tool":"transfer","arguments":{"from_account":"a","to_account":"b","amount_cents":1,"amount_cents":2,"currency":"USD"}}`, errSub: `duplicate field "amount_cents"`},
		{name: "duplicate tool", body: `{"tool":"transfer","tool":"ping","arguments":{}}`, errSub: `duplicate field "tool"`},
		{name: "unknown top level", body: `{"tool":"ping","arguments":{},"trace_id":"abc"}`, errSub: `unknown field "trace_id" in request`},
		{name: "unknown top level sorts first", body: `{"zzz":1,"aaa":2,"tool":"ping","arguments":{}}`, errSub: `unknown field "aaa" in request`},
		{name: "ping rejects fields", body: `{"tool":"ping","arguments":{"x":1}}`, errSub: `unknown field "x"`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := schema.Validate(catalog(), []byte(tc.body))
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.errSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.errSub)
			}
			var schemaErr *schema.Error
			if !errors.As(err, &schemaErr) {
				t.Fatalf("error type %T", err)
			}
		})
	}
}

func TestValidateAccepts(t *testing.T) {
	tests := []struct {
		name  string
		body  string
		check func(t *testing.T, call schema.Call)
	}{
		{
			name: "transfer of one cent",
			body: transfer("1"),
			check: func(t *testing.T, call schema.Call) {
				if call.Tool != "transfer" || call.Args["amount_cents"].Int != 1 {
					t.Fatalf("%+v", call)
				}
				if _, ok := call.Args["memo"]; ok {
					t.Fatal("omitted memo should be absent")
				}
			},
		},
		{
			name: "exactly 500 dollars",
			body: transfer("50000"),
			check: func(t *testing.T, call schema.Call) {
				if call.Args["amount_cents"].Int != 50000 {
					t.Fatal(call.Args["amount_cents"].Int)
				}
			},
		},
		{
			name: "one cent over 500 dollars",
			body: transfer("50001"),
			check: func(t *testing.T, call schema.Call) {
				if call.Args["amount_cents"].Int != 50001 {
					t.Fatal(call.Args["amount_cents"].Int)
				}
			},
		},
		{
			name: "negative amount is still an integer",
			body: transfer("-50001"),
			check: func(t *testing.T, call schema.Call) {
				if call.Args["amount_cents"].Int != -50001 {
					t.Fatal(call.Args["amount_cents"].Int)
				}
			},
		},
		{
			name: "negative zero",
			body: transfer("-0"),
			check: func(t *testing.T, call schema.Call) {
				if call.Args["amount_cents"].Int != 0 {
					t.Fatal(call.Args["amount_cents"].Int)
				}
			},
		},
		{
			name: "past float64 mantissa",
			body: transfer("9007199254740993"),
			check: func(t *testing.T, call schema.Call) {
				if call.Args["amount_cents"].Int != 9007199254740993 {
					t.Fatalf("got %d", call.Args["amount_cents"].Int)
				}
			},
		},
		{
			name: "max int64",
			body: transfer(strconv.FormatInt(math.MaxInt64, 10)),
			check: func(t *testing.T, call schema.Call) {
				if call.Args["amount_cents"].Int != math.MaxInt64 {
					t.Fatal(call.Args["amount_cents"].Int)
				}
			},
		},
		{
			name: "memo and expedite false",
			body: `{"tool":"transfer","arguments":{"from_account":"a","to_account":"b","amount_cents":100,"currency":"USD","memo":"café","expedite":false}}`,
			check: func(t *testing.T, call schema.Call) {
				if call.Args["memo"].Str != "café" {
					t.Fatalf("memo %q", call.Args["memo"].Str)
				}
				if call.Args["expedite"].Type != schema.TypeBoolean || call.Args["expedite"].Bool {
					t.Fatalf("expedite %+v", call.Args["expedite"])
				}
			},
		},
		{
			name: "expedite true",
			body: `{"tool":"transfer","arguments":{"from_account":"a","to_account":"b","amount_cents":100,"currency":"USD","expedite":true}}`,
			check: func(t *testing.T, call schema.Call) {
				if !call.Args["expedite"].Bool {
					t.Fatal("expected true")
				}
			},
		},
		{
			name: "ping",
			body: `{"tool":"ping","arguments":{}}`,
			check: func(t *testing.T, call schema.Call) {
				if call.Tool != "ping" || len(call.Args) != 0 {
					t.Fatalf("%+v", call)
				}
			},
		},
		{
			name: "surrounding whitespace",
			body: "\n" + transfer("100") + "\n",
			check: func(t *testing.T, call schema.Call) {
				if call.Args["amount_cents"].Int != 100 {
					t.Fatal(call.Args["amount_cents"].Int)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			call, err := schema.Validate(catalog(), []byte(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, call)
		})
	}
}
