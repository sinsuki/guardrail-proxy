# guardrail-proxy

Deterministic guardrail for financial AI agents. An agent sends a tool call as JSON (a tool name and its arguments). This proxy checks the call against a strict schema and a business-rule file, then forwards it only when the rules allow it.

The calls in view are ones that move money, read a balance, or change a stored record. The proxy does not authenticate the caller and does not replace the upstream API's own authorization. It stops malformed calls, and it applies the rules in the policy file, before anything is forwarded.

This tree has the schema, the rule engine, a human approval webhook, PII redaction on the path to an LLM, and a signed hash-chained audit log. A later milestone adds a demo agent.

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

## PII redaction

`POST /v1/llm` redacts a prompt, forwards it to the `-llm` URL, and puts the originals back in the reply. The mapping lives only for that request. It is not written to the LLM, to logs, or to the financial API. Tool calls to the bank still carry real account numbers, because the bank has to see them.

Each value becomes a stable placeholder such as `[EMAIL_1]`. The same email twice in one prompt shares one placeholder, so the model can refer to it and the proxy can fill it back in, including inside a tool call in the reply.

The matcher looks for:

- email addresses
- US phone numbers that include separators, a leading `+`, or a phone label, and E.164 numbers
- SSNs written as `ddd-dd-dddd` or `ddd dd dddd`, excluding the well-known invalid ranges
- card numbers of 13 to 19 digits that pass the Luhn check, with spaces or dashes allowed
- US routing numbers that pass the ABA checksum and prefix ranges
- account numbers of 6 to 17 digits that sit next to a word like `account`, `checking`, or `savings`
- IBANs that pass the mod-97 check

It does not try to find names or street addresses. Those are not regular enough, and a name list would both miss people and flag ordinary words. It also misses obfuscation (`ada at example dot com`), a phone number written as ten digits with no label or separators, and an account number with no nearby label. A 16-digit order id that happens to pass Luhn, or a 9-digit id that happens to pass the ABA check, can still be flagged. That is the limit of this kind of scan.

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

`-decision deny` makes the same call return 403 and skips the upstream. `GET /healthz` returns `ok`. Tool-call bodies are limited to 64 KiB. LLM bodies are limited to 1 MiB. The upstream URL, the webhook URL, and the LLM URL come from flags; the request cannot choose them.

To redact prompts, start a stand-in model and pass `-llm`:

```bash
go run ./cmd/fakellm -listen 127.0.0.1:8083
go run ./cmd/proxy -config policy.json \
  -upstream http://127.0.0.1:8081/ \
  -llm http://127.0.0.1:8083/ \
  -listen 127.0.0.1:8080
```

```bash
curl -sS -D- http://127.0.0.1:8080/v1/llm \
  -H 'content-type: application/json' \
  -d '{"messages":[{"role":"user","content":"email ada@example.com about the transfer"}]}'
```

The model sees `[EMAIL_1]`. The curl response has `ada@example.com` again. `X-Guardrail-Redacted` counts kinds, not values.

## Audit log

With `-audit-log` and `-audit-key`, every tool call, schema result, rule decision, approval request, approval answer, LLM redaction, and forward is an append-only JSON line. Each line stores the SHA-256 of the previous line and an Ed25519 signature over its own contents. Changing, deleting, reordering, or inserting a line breaks the chain. A signed tip file next to the log (`audit.jsonl.tip`) records the last sequence number, so chopping lines off the end is visible too.

The private key is created on the machine that writes the log. It is not part of this repo.

```bash
go run ./cmd/audit keygen -out audit.key
go run ./cmd/proxy -config policy.json \
  -upstream http://127.0.0.1:8081/ \
  -audit-log audit.jsonl -audit-key audit.key \
  -listen 127.0.0.1:8080
go run ./cmd/audit verify -log audit.jsonl -pub audit.pub
```

`verify` checks the chain with the public key and prints the first bad entry. Restarting the proxy resumes from the last signed line. Tool calls are stored as a SHA-256 of the raw body, not the body itself. LLM events store redaction counts by type and do not store the text or the placeholder map.

## Tests

```bash
go test ./...
go vet ./...
go test -race ./...
go test ./internal/check ./internal/approval ./internal/proxy ./internal/redact ./internal/audit -bench=. -benchmem
```

## Layout

- `internal/schema` validates one tool call.
- `internal/rules` returns `allow`, `deny`, or `needs_approval`.
- `internal/config` loads the policy file.
- `internal/check` runs the schema check, then the rules.
- `internal/approval` signs and checks one webhook decision.
- `internal/proxy` is the tool-call HTTP endpoint.
- `internal/redact` replaces PII with placeholders and restores them.
- `internal/llm` redacts a prompt, forwards it, and restores the reply.
- `internal/fakeupstream` is the stand-in API.
- `internal/fakeapprover` is the stand-in webhook.
- `internal/fakellm` is the stand-in model.
- `internal/audit` is the hash-chained log. `cmd/audit` generates a key and verifies a log.

## License

MIT.
