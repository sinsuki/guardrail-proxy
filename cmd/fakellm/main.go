// Command fakellm serves the stand-in model used for local runs.
package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/sinsuki/guardrail-proxy/internal/fakellm"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8083", "listen address")
	flag.Parse()
	srv := &http.Server{
		Addr:              *listen,
		Handler:           fakellm.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	log.SetPrefix("fakellm: ")
	log.Printf("listening on %s", *listen)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
