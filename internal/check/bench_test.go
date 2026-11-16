package check_test

import "testing"

func BenchmarkCheck(b *testing.B) {
	c := loadChecker(b)
	cases := []struct {
		name string
		body string
		fail bool
	}{
		{name: "allow_500_00", body: transfer("50000")},
		{name: "needs_approval_500_01", body: transfer("50001")},
		{name: "deny_negative", body: transfer("-1")},
		{name: "reject_float", body: transfer("500.01"), fail: true},
	}
	for _, tc := range cases {
		body := []byte(tc.body)
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := c.Check(body)
				if tc.fail {
					if err == nil {
						b.Fatal("expected error")
					}
					continue
				}
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
