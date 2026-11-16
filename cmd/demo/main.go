// Command demo plays the proxy scenario with local stand-ins.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/sinsuki/guardrail-proxy/internal/demo"
)

func main() {
	policy := flag.String("policy", "policy.json", "policy file")
	llmURL := flag.String("llm", "", "OpenAI-compatible chat completions URL; empty uses the local stand-in")
	llmKey := flag.String("llm-key", os.Getenv("OPENAI_API_KEY"), "bearer token for -llm")
	llmModel := flag.String("llm-model", "gpt-4o-mini", "model name when -llm is set")
	flag.Parse()

	err := demo.Run(context.Background(), os.Stdout, demo.Options{
		PolicyPath: *policy,
		LLMURL:     *llmURL,
		LLMKey:     *llmKey,
		LLMModel:   *llmModel,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "demo: %v\n", err)
		os.Exit(1)
	}
}
