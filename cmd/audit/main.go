// Command audit generates an Ed25519 key and verifies a hash-chained log.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/sinsuki/guardrail-proxy/internal/audit"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "keygen":
		fs := flag.NewFlagSet("keygen", flag.ExitOnError)
		out := fs.String("out", "audit.key", "private key path")
		_ = fs.Parse(os.Args[2:])
		pub := publicPath(*out)
		if err := audit.GenerateKey(*out, pub); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		fmt.Printf("wrote %s and %s\n", *out, pub)
	case "verify":
		fs := flag.NewFlagSet("verify", flag.ExitOnError)
		logPath := fs.String("log", "audit.jsonl", "audit log path")
		pub := fs.String("pub", "audit.pub", "hex Ed25519 public key")
		_ = fs.Parse(os.Args[2:])
		n, err := audit.Verify(*logPath, *pub)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
		fmt.Printf("ok entries=%d\n", n)
	default:
		usage()
		os.Exit(2)
	}
}

func publicPath(priv string) string {
	if strings.HasSuffix(priv, ".key") {
		return strings.TrimSuffix(priv, ".key") + ".pub"
	}
	return priv + ".pub"
}

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  audit keygen -out audit.key
  audit verify -log audit.jsonl -pub audit.pub
`)
}
