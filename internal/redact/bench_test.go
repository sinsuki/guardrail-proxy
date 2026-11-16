package redact_test

import (
	"testing"

	"github.com/sinsuki/guardrail-proxy/internal/redact"
)

func BenchmarkRedactPrompt(b *testing.B) {
	const prompt = `A customer wrote in about a failed transfer. Their note says:
Hi, this is a follow-up on the payment that did not post. You can reach me at
ada@example.com or on (415) 555-0130. The card I used was 4111 1111 1111 1111.
The bank routing number is 021000021 and the checking account number is
123456789012. Tax id on the form is 123-45-6789. IBAN for the other side is
GB82WEST12345698765432. The invoice total was $500.00, which is 50000 cents,
and the ticket number is 123456789. Please reply about the same email address
ada@example.com so I can match the thread. Thanks.`
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, vault := redact.Redact(prompt)
		if out == prompt || len(vault.Counts()) == 0 {
			b.Fatal("expected redactions")
		}
	}
}
