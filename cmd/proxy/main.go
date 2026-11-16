// Command proxy checks agent tool calls and forwards the ones the policy allows.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/sinsuki/guardrail-proxy/internal/approval"
	"github.com/sinsuki/guardrail-proxy/internal/config"
	"github.com/sinsuki/guardrail-proxy/internal/proxy"
)

func main() {
	configPath := flag.String("config", "policy.json", "policy file")
	upstream := flag.String("upstream", "", "absolute http(s) URL that receives allowed tool calls")
	listen := flag.String("listen", "127.0.0.1:8080", "listen address")
	approvalWebhook := flag.String("approval-webhook", "", "absolute http(s) URL that decides needs_approval calls")
	approvalSecret := flag.String("approval-secret", "", "HMAC secret for the approval webhook; overrides GUARDRAIL_APPROVAL_SECRET")
	approvalTimeout := flag.Duration("approval-timeout", 5*time.Second, "how long to wait for an approval before denying")
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

	var opts []proxy.Option
	if *approvalWebhook != "" {
		secret := *approvalSecret
		if secret == "" {
			secret = os.Getenv("GUARDRAIL_APPROVAL_SECRET")
		}
		client, err := approval.NewClient(*approvalWebhook, secret, *approvalTimeout, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		opts = append(opts, proxy.WithApproval(client))
	}

	handler, err := proxy.New(policy, *upstream, nil, opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	writeTimeout := 30 * time.Second
	if *approvalTimeout+20*time.Second > writeTimeout {
		writeTimeout = *approvalTimeout + 20*time.Second
	}
	srv := &http.Server{
		Addr:              *listen,
		Handler:           handler.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       60 * time.Second,
	}
	log.SetPrefix("proxy: ")
	if *approvalWebhook == "" {
		log.Printf("listening on %s", *listen)
	} else {
		log.Printf("listening on %s approval timeout %s", *listen, approvalTimeout.String())
	}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
