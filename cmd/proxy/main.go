// Command proxy checks agent tool calls and forwards the ones the policy allows.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/sinsuki/guardrail-proxy/internal/config"
	"github.com/sinsuki/guardrail-proxy/internal/proxy"
)

func main() {
	configPath := flag.String("config", "policy.json", "policy file")
	upstream := flag.String("upstream", "", "absolute http(s) URL that receives allowed tool calls")
	listen := flag.String("listen", "127.0.0.1:8080", "listen address")
	flag.Parse()

	if *upstream == "" {
		fmt.Fprintln(os.Stderr, "missing required flag -upstream")
		flag.Usage()
		os.Exit(2)
	}

	policy, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	handler, err := proxy.New(policy, *upstream, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	srv := &http.Server{
		Addr:              *listen,
		Handler:           handler.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.SetPrefix("proxy: ")
	log.Printf("listening on %s", *listen)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
