// Package fakeupstream is a stand-in financial API for tests and local runs.
// It echoes the POST body. It does not move money.
package fakeupstream

import (
	"io"
	"log"
	"net/http"
)

const maxBody = 1 << 20

// Handler accepts POST of a tool call and returns it inside a JSON envelope.
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
		if len(body) == 0 {
			body = []byte("null")
		}
		log.Printf("%s %s %d bytes", r.Method, r.URL.Path, len(body))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true,"received":`))
		_, _ = w.Write(body)
		_, _ = w.Write([]byte(`}`))
	})
}
