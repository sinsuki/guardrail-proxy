// Command fakeapprover serves the stand-in approval webhook used for local runs.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/sinsuki/guardrail-proxy/internal/fakeapprover"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8082", "listen address")
	secret := flag.String("secret", "", "HMAC secret shared with the proxy; overrides GUARDRAIL_APPROVAL_SECRET")
	decision := flag.String("decision", "deny", "approve or deny")
	flag.Parse()

	key := *secret
	if key == "" {
		key = os.Getenv("GUARDRAIL_APPROVAL_SECRET")
	}
	if len(key) < 16 {
		fmt.Fprintln(os.Stderr, "approval secret must be at least 16 bytes (-secret or GUARDRAIL_APPROVAL_SECRET)")
		os.Exit(2)
	}
	if *decision != "approve" && *decision != "deny" {
		fmt.Fprintln(os.Stderr, `-decision must be "approve" or "deny"`)
		os.Exit(2)
	}

	srv := &http.Server{
		Addr:              *listen,
		Handler:           fakeapprover.New(key, *decision).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	log.SetPrefix("fakeapprover: ")
	log.Printf("listening on %s decision=%s", *listen, *decision)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
