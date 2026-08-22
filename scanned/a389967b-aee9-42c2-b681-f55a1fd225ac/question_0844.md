# Q0844: token attached to non-matching host - findEndCursor in pagination.go

## Question
Can `findEndCursor` in [pkg/cmd/api/pagination.go](pkg/cmd/api/pagination.go#L26) attach the token stored for one host to a request whose host was derived from a repo/remote/host string or API response field the attacker publishes?

## Target
- File/function: [pkg/cmd/api/pagination.go:26](pkg/cmd/api/pagination.go#L26) - `findEndCursor`
- Entrypoint: gh api pagination
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish a repo/remote that resolves to a host the attacker controls while the victim's active token is for github.com.
- Invariant to test: A token is only ever sent to the exact host it was issued for.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Unit test with two configured hosts asserting the header matches the request host.
