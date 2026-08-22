# Q5781: DNS rebinding between check and connect - printHeaders in api.go

## Question
Does `printHeaders` in [pkg/cmd/api/api.go](pkg/cmd/api/api.go#L613) validate a hostname and then dial it later, allowing a rebinding attacker to pass the check and serve a different address?

## Target
- File/function: [pkg/cmd/api/api.go:613](pkg/cmd/api/api.go#L613) - `printHeaders`
- Entrypoint: gh api
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Serve a short-TTL record that flips after validation.
- Invariant to test: Validation is host-based and enforced at dial time by the same transport.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting validation happens in the transport, not only before it.
