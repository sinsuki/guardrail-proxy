// Package fakellm is a stand-in model endpoint for tests and local runs.
// It echoes the request it received. It does not call a model.
package fakellm

import (
	"io"
	"log"
	"net/http"
	"regexp"
)

const maxBody = 1 << 20

var placeholderRE = regexp.MustCompile(`\[[A-Z]+_\d+\]`)

// Handler returns the redacted request and, when a placeholder is present,
// a tool call that repeats the first one.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			http.Error(w, "request body is too large", http.StatusRequestEntityTooLarge)
			return
		}
		log.Printf("received %d bytes", len(body))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"fake","echo":`))
		writeJSONString(w, string(body))
		if tok := placeholderRE.Find(body); tok != nil {
			_, _ = w.Write([]byte(`,"tool_call":{"name":"send_note","arguments":{"to":`))
			writeJSONString(w, string(tok))
			_, _ = w.Write([]byte(`}}`))
		}
		_, _ = w.Write([]byte(`}`))
	})
}

func writeJSONString(w http.ResponseWriter, s string) {
	var b []byte
	b = append(b, '"')
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\', '"':
			b = append(b, '\\', s[i])
		case '\n':
			b = append(b, '\\', 'n')
		case '\r':
			b = append(b, '\\', 'r')
		case '\t':
			b = append(b, '\\', 't')
		default:
			b = append(b, s[i])
		}
	}
	b = append(b, '"')
	_, _ = w.Write(b)
}
