package redact_test

import (
	"strings"
	"testing"

	"github.com/sinsuki/guardrail-proxy/internal/redact"
)

func TestRedact(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "email", in: "mail ada@example.com now", want: "mail [EMAIL_1] now"},
		{name: "same email twice", in: "ada@example.com and ada@example.com", want: "[EMAIL_1] and [EMAIL_1]"},
		{name: "two emails", in: "ada@example.com and bob@example.org", want: "[EMAIL_1] and [EMAIL_2]"},
		{name: "phone parens", in: "call (415) 555-0130 today", want: "call [PHONE_1] today"},
		{name: "phone dashes", in: "call 415-555-0130 today", want: "call [PHONE_1] today"},
		{name: "phone e164", in: "call +14155550130 today", want: "call [PHONE_1] today"},
		{name: "labeled phone", in: "phone: 4155550130", want: "phone: [PHONE_1]"},
		{name: "ssn", in: "ssn 123-45-6789 on file", want: "ssn [SSN_1] on file"},
		{name: "ssn spaces", in: "ssn 123 45 6789 on file", want: "ssn [SSN_1] on file"},
		{name: "card digits", in: "card 4111111111111111 ok", want: "card [CARD_1] ok"},
		{name: "card spaces", in: "card 4111 1111 1111 1111 ok", want: "card [CARD_1] ok"},
		{name: "card dashes", in: "card 4111-1111-1111-1111 ok", want: "card [CARD_1] ok"},
		{name: "same card twice", in: "4111111111111111 and 4111111111111111", want: "[CARD_1] and [CARD_1]"},
		{name: "routing", in: "routing 021000021 please", want: "routing [ROUTING_1] please"},
		{name: "account label", in: "account 9876543210 please", want: "account [ACCOUNT_1] please"},
		{name: "account number is", in: "checking account number is 123456789012 now", want: "checking account number is [ACCOUNT_1] now"},
		{name: "acct hash", in: "acct #12345678 please", want: "acct #[ACCOUNT_1] please"},
		{name: "iban", in: "iban GB82WEST12345698765432 now", want: "iban [IBAN_1] now"},
		{name: "iban spaces", in: "iban GB82 WEST 1234 5698 7654 32 now", want: "iban [IBAN_1] now"},
		{name: "mixed stable", in: "ada@example.com paid 4111111111111111 from ada@example.com", want: "[EMAIL_1] paid [CARD_1] from [EMAIL_1]"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, vault := redact.Redact(tc.in)
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
			if back := vault.Restore(got); back != tc.in {
				t.Fatalf("restore %q want %q", back, tc.in)
			}
		})
	}
}

func TestRejectsLookalikes(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{name: "bad luhn", in: "card 4111111111111112 on the order"},
		{name: "all zero card", in: "code 0000000000000000"},
		{name: "short digits", in: "ticket 12345"},
		{name: "nine digits fail aba", in: "ref 123456789"},
		{name: "bad routing checksum", in: "routing 021000022"},
		{name: "ssn area 000", in: "id 000-12-3456"},
		{name: "ssn group 00", in: "id 123-00-6789"},
		{name: "ssn serial 0000", in: "id 123-45-0000"},
		{name: "ssn 666", in: "id 666-12-3456"},
		{name: "ssn 900", in: "id 900-12-3456"},
		{name: "date", in: "on 2024-11-16"},
		{name: "money", in: "price $500.00 and 50000 cents"},
		{name: "version", in: "build v1.2.3"},
		{name: "unlabeled account", in: "memo 9876543210"},
		{name: "bare phone", in: "code 4155550130"},
		{name: "invalid area phone", in: "call 115-555-0130"},
		{name: "words", in: "not an email and not a phone"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, vault := redact.Redact(tc.in)
			if got != tc.in {
				t.Fatalf("redacted %q into %q", tc.in, got)
			}
			if len(vault.Counts()) != 0 {
				t.Fatalf("counts %v", vault.Counts())
			}
		})
	}
}

func TestRestoreToolCall(t *testing.T) {
	_, vault := redact.Redact("send the receipt to ada@example.com")
	reply := `{"tool_call":{"name":"send_note","arguments":{"to":"[EMAIL_1]"}}}`
	got := vault.Restore(reply)
	if !strings.Contains(got, "ada@example.com") || strings.Contains(got, "[EMAIL_1]") {
		t.Fatalf("%s", got)
	}
}

func TestRedactJSONPreservesNumbers(t *testing.T) {
	in := []byte(`{"amount_cents":50001,"big":9007199254740993,"note":"card 4111111111111111 for ada@example.com"}`)
	out, vault, err := redact.RedactJSON(in)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if !strings.Contains(text, `"amount_cents":50001`) {
		t.Fatalf("amount changed: %s", text)
	}
	if !strings.Contains(text, `"big":9007199254740993`) {
		t.Fatalf("big int changed: %s", text)
	}
	if strings.Contains(text, "4111111111111111") || strings.Contains(text, "ada@example.com") {
		t.Fatalf("pii leaked: %s", text)
	}
	if !strings.Contains(text, "[CARD_1]") || !strings.Contains(text, "[EMAIL_1]") {
		t.Fatalf("placeholders missing: %s", text)
	}
	back, err := vault.RestoreJSON(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(back), "4111111111111111") || !strings.Contains(string(back), "ada@example.com") {
		t.Fatalf("restore %s", back)
	}
}

// corpusItem is one labeled example. catch must disappear, keep must remain,
// and gap is real PII the matcher is expected to miss.
type corpusItem struct {
	name  string
	text  string
	catch []string
	keep  []string
	gap   []string
}

func corpus() []corpusItem {
	return []corpusItem{
		{name: "email", text: "Write ada@example.com today", catch: []string{"ada@example.com"}, keep: []string{"Write", "today"}},
		{name: "second email", text: "bob@example.org", catch: []string{"bob@example.org"}},
		{name: "phone", text: "Ring (415) 555-0130 please", catch: []string{"(415) 555-0130"}, keep: []string{"Ring", "please"}},
		{name: "phone dashes", text: "Ring 415-555-0199 please", catch: []string{"415-555-0199"}},
		{name: "e164", text: "Ring +14155550130 please", catch: []string{"+14155550130"}},
		{name: "ssn", text: "SSN 123-45-6789 here", catch: []string{"123-45-6789"}, keep: []string{"SSN", "here"}},
		{name: "card", text: "Visa 4111111111111111 now", catch: []string{"4111111111111111"}},
		{name: "card spaced", text: "Visa 4111 1111 1111 1111 now", catch: []string{"4111 1111 1111 1111"}},
		{name: "mastercard", text: "MC 5555555555554444 now", catch: []string{"5555555555554444"}},
		{name: "routing", text: "ABA 021000021 now", catch: []string{"021000021"}, keep: []string{"ABA"}},
		{name: "account", text: "checking 123456789012 now", catch: []string{"123456789012"}, keep: []string{"checking"}},
		{name: "iban", text: "IBAN GB82WEST12345698765432 now", catch: []string{"GB82WEST12345698765432"}},
		{name: "bad luhn", text: "order 4111111111111112", keep: []string{"4111111111111112", "order"}},
		{name: "zeros", text: "order 0000000000000000", keep: []string{"0000000000000000"}},
		{name: "random nine", text: "ticket 123456789", keep: []string{"123456789"}},
		{name: "bad aba", text: "ticket 021000022", keep: []string{"021000022"}},
		{name: "bad ssn", text: "ticket 000-12-3456", keep: []string{"000-12-3456"}},
		{name: "date", text: "due 2024-11-16", keep: []string{"2024-11-16"}},
		{name: "cents", text: "amount_cents is 50000", keep: []string{"50000", "amount_cents"}},
		{name: "price", text: "price $500.00", keep: []string{"$500.00"}},
		{name: "unlabeled account", text: "memo 9876543210", keep: []string{"9876543210"}},
		{name: "bare digits phone shaped", text: "code 4155550130", keep: []string{"4155550130"}},
		{name: "exchange starts with 1", text: "call 415-155-0130", keep: []string{"415-155-0130"}},
		{name: "name", text: "Customer Jane Q. Public called", keep: []string{"Jane Q. Public"}, gap: []string{"Jane Q. Public"}},
		{name: "street", text: "Ship to 123 Main Street, Springfield", keep: []string{"123 Main Street"}, gap: []string{"123 Main Street"}},
		{name: "obfuscated email", text: "reach ada at example dot com", keep: []string{"ada at example dot com"}, gap: []string{"ada at example dot com"}},
		{name: "split card", text: "card ending 1111 only", keep: []string{"1111"}},
	}
}

func TestCorpusCounts(t *testing.T) {
	var fp, fn, known, catchN, keepN int
	for _, item := range corpus() {
		out, _ := redact.Redact(item.text)
		for _, c := range item.catch {
			catchN++
			if strings.Contains(out, c) {
				fn++
				t.Errorf("%s: missed %q in %q", item.name, c, out)
			}
		}
		for _, k := range item.keep {
			keepN++
			if !strings.Contains(out, k) {
				fp++
				t.Errorf("%s: redacted non-PII %q in %q", item.name, k, out)
			}
		}
		for _, g := range item.gap {
			known++
			if !strings.Contains(out, g) {
				t.Errorf("%s: unexpectedly redacted known gap %q", item.name, g)
			}
		}
	}
	t.Logf("corpus_items=%d catch=%d keep=%d false_positives=%d false_negatives=%d known_misses=%d",
		len(corpus()), catchN, keepN, fp, fn, known)
	if fp != 0 || fn != 0 {
		t.Fatalf("false_positives=%d false_negatives=%d", fp, fn)
	}
	if known != 3 {
		t.Fatalf("known_misses=%d", known)
	}
}
