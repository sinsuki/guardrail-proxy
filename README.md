# guardrail-proxy

Deterministic guardrail for financial AI agents. An agent sends a tool call as JSON (a tool name and its arguments). This proxy checks the call against a strict schema and a business-rule file, then forwards it only when the rules allow it.

The calls in view are ones that move money, read a balance, or change a stored record. The proxy does not authenticate the caller and does not replace the upstream API's own authorization. It stops malformed calls, and it applies the rules in the policy file, before anything is forwarded.

This tree has the schema, the rule engine, and a human approval webhook. Later milestones add PII redaction, a signed hash-chained audit log, and a demo agent.

## Policy

`policy.json` is a working sample. Integer fields are base-10 JSON integers in the int64 range. `500.00`, `1e2`, and `"50000"` are rejected. Integers are read from the JSON text, so a value past the float64 mantissa stays exact. Money is integer cents: one dollar is `100`, and five hundred dollars is `50000`.

Rules run in file order. The first match wins. If none match, the decision is `allow`. Integer fields accept `eq`, `ne`, `lt`, `lte`, `gt`, and `gte`. String and boolean fields accept `eq` and `ne`. A rule can only name a required field.

The sample has two transfer rules:

- `amount_cents < 1` is `deny`. Zero and negative amounts are denied, including a negative whose magnitude is over $500.
- `amount_cents > 50000` is `needs_approval`. That is anything over $500.00.

A transfer of exactly `50000` cents is allowed. The sample rule does not read the currency code and does not convert currencies.

## Approval

When `-approval-webhook` is set, a `needs_approval` call is posted to that URL and the proxy waits. The webhook returns `approve` or `deny`. Only `approve` is forwarded. A timeout, a bad signature, a mismatched call, or a reused decision is a denial and is not forwarded.

The shared secret is `GUARDRAIL_APPROVAL_SECRET` or `-approval-secret`. It is not stored in `policy.json`. It must be at least 16 bytes. Each side signs the raw JSON body with HMAC-SHA256 (`X-Guardrail-Signature: v1=...`). The signed decision includes the request id and the SHA-256 of the exact tool-call bytes, so an approval for one amount cannot be applied to another. The request id is single-use. The proxy stops waiting after `-approval-timeout` (default 5s) and denies the call.

The proxy holds the agent request open while the webhook decides. Closing that connection denies the call. Without `-approval-webhook`, `needs_approval` is still not forwarded.

## Run

From the repo root, start the stand-in API and the proxy:

```bash
go run ./cmd/fakeupstream -listen 127.0.0.1:8081
go run ./cmd/proxy -config policy.json -upstream http://127.0.0.1:8081/ -listen 127.0.0.1:8080
```

Exactly $500.00 is allowed without a webhook. The upstream body is returned as-is, with `X-Guardrail-Decision: allow`:

```bash
curl -sS -D- http://127.0.0.1:8080/v1/tool-calls \
  -H 'content-type: application/json' \
  -d '{"tool":"transfer","arguments":{"from_account":"acct_1","to_account":"acct_2","amount_cents":50000,"currency":"USD"}}'
```

For a transfer over $500.00, stop that proxy and start an approver. The secret below is a local development value.

```bash
export GUARDRAIL_APPROVAL_SECRET=dev-approval-secret
go run ./cmd/fakeapprover -listen 127.0.0.1:8082 -decision approve
go run ./cmd/proxy -config policy.json \
  -upstream http://127.0.0.1:8081/ \
  -approval-webhook http://127.0.0.1:8082/ \
  -listen 127.0.0.1:8080
```

```bash
curl -sS -D- http://127.0.0.1:8080/v1/tool-calls \
  -H 'content-type: application/json' \
  -d '{"tool":"transfer","arguments":{"from_account":"acct_1","to_account":"acct_2","amount_cents":50001,"currency":"USD"}}'
```

`-decision deny` makes the same call return 403 and skips the upstream. `GET /healthz` returns `ok`. Request bodies are limited to 64 KiB. The upstream URL and the webhook URL come from flags; the request cannot choose them.

## Tests

```bash
go test ./...
go vet ./...
go test -race ./...
go test ./internal/check ./internal/approval ./internal/proxy -bench=. -benchmem
```

## Layout

- `internal/schema` validates one tool call.
- `internal/rules` returns `allow`, `deny`, or `needs_approval`.
- `internal/config` loads the policy file.
- `internal/check` runs the schema check, then the rules.
- `internal/approval` signs and checks one webhook decision.
- `internal/proxy` is the HTTP endpoint.
- `internal/fakeupstream` is the stand-in API.
- `internal/fakeapprover` is the stand-in webhook.

## License

MIT.
