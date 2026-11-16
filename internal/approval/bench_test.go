package approval_test

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/sinsuki/guardrail-proxy/internal/approval"
)

func BenchmarkDecisionCrypto(b *testing.B) {
	secret := []byte(testSecret)
	call := callBody("50001")
	callHash := approval.Hash(call)
	exp := time.Now().Add(time.Hour).UTC()
	expStr := exp.Format(time.RFC3339Nano)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := strconv.Itoa(i)
		raw, err := json.Marshal(approval.Response{
			RequestID:  id,
			Decision:   "approve",
			CallSHA256: callHash,
			ExpiresAt:  expStr,
		})
		if err != nil {
			b.Fatal(err)
		}
		// A new set each time measures one decision, not a map that grows with b.N.
		_, err = approval.Check(secret, approval.Pending{
			ID:        id,
			CallHash:  callHash,
			ExpiresAt: expStr,
			Expires:   exp,
		}, approval.NewUsed(time.Hour), raw, approval.Sign(secret, raw), time.Now())
		if err != nil {
			b.Fatal(err)
		}
	}
}
