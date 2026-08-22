# Q3700: scheme downgrade on redirect - findEndCursor in pagination.go

## Question
Can a redirect followed by `findEndCursor` in [pkg/cmd/api/pagination.go](pkg/cmd/api/pagination.go#L26) downgrade https to http (or to a non-HTTP scheme) while still sending credentials?

## Target
- File/function: [pkg/cmd/api/pagination.go:26](pkg/cmd/api/pagination.go#L26) - `findEndCursor`
- Entrypoint: gh api pagination
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Redirect to `http://collector/` and observe the token in cleartext.
- Invariant to test: Only https targets are followed; other schemes abort the request.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting an http:// Location produces an error and no request is sent.
