// Command fakeupstream serves the stand-in financial API used for local runs.
package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/sinsuki/guardrail-proxy/internal/fakeupstream"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8081", "listen address")
	flag.Parse()

	srv := &http.Server{
		Addr:              *listen,
		Handler:           fakeupstream.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	log.SetPrefix("fakeupstream: ")
	log.Printf("listening on %s", *listen)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
