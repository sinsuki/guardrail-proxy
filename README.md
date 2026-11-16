# guardrail-proxy

Deterministic guardrail for financial AI agents. An agent sends a tool call as JSON (a tool name and its arguments). This proxy checks the call against a strict schema and a business-rule file, then forwards it only when the rules allow it.

The calls in view are ones that move money, read a balance, or change a stored record. The proxy does not authenticate the caller and does not replace the upstream API's own authorization. It stops malformed calls, and it applies the rules in the policy file, before anything is forwarded.

This repository is milestone 1: schemas, the rule engine, and the HTTP proxy. Later milestones add a human approval webhook, PII redaction, a signed hash-chained audit log, and a demo agent. A rule can already return `needs_approval`. The proxy keeps that decision and does not forward the call, because the webhook is not built yet.

## Policy

`policy.json` is a working sample. Integer fields are base-10 JSON integers in the int64 range. `500.00`, `1e2`, and `"50000"` are rejected. Integers are read from the JSON text, so a value past the float64 mantissa stays exact. Money is integer cents: one dollar is `100`, and five hundred dollars is `50000`.

Rules run in file order. The first match wins. If none match, the decision is `allow`. Integer fields accept `eq`, `ne`, `lt`, `lte`, `gt`, and `gte`. String and boolean fields accept `eq` and `ne`. A rule can only name a required field.

The sample has two transfer rules:

- `amount_cents < 1` is `deny`. Zero and negative amounts are denied, including a negative whose magnitude is over $500.
- `amount_cents > 50000` is `needs_approval`. That is anything over $500.00.

A transfer of exactly `50000` cents is allowed. A transfer of `50001` cents is not forwarded. The sample rule does not read the currency code and does not convert currencies.

## Run

From the repo root, start the stand-in API and the proxy:

```bash
go run ./cmd/fakeupstream -listen 127.0.0.1:8081
go run ./cmd/proxy -config policy.json -upstream http://127.0.0.1:8081/ -listen 127.0.0.1:8080
```

Exactly $500.00. The upstream body is returned as-is, with `X-Guardrail-Decision: allow`:

```bash
curl -sS -D- http://127.0.0.1:8080/v1/tool-calls \
  -H 'content-type: application/json' \
  -d '{"tool":"transfer","arguments":{"from_account":"acct_1","to_account":"acct_2","amount_cents":50000,"currency":"USD"}}'
```

One cent over $500.00. The proxy answers `403` and does not call the upstream:

```bash
curl -sS -D- http://127.0.0.1:8080/v1/tool-calls \
  -H 'content-type: application/json' \
  -d '{"tool":"transfer","arguments":{"from_account":"acct_1","to_account":"acct_2","amount_cents":50001,"currency":"USD"}}'
```

`GET /healthz` returns `ok`. Request bodies are limited to 64 KiB. The upstream URL is the `-upstream` flag; the request cannot choose it.

## Tests

```bash
go test ./...
go vet ./...
go test ./internal/check -bench=BenchmarkCheck -benchmem
```

## Layout

- `internal/schema` validates one tool call.
- `internal/rules` returns `allow`, `deny`, or `needs_approval`.
- `internal/config` loads the policy file.
- `internal/check` runs the schema check, then the rules.
- `internal/proxy` is the HTTP endpoint.
- `internal/fakeupstream` is the stand-in API.

## License

MIT.
