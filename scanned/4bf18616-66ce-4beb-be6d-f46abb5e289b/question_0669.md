# Q0669: scheme downgrade on redirect - newCAPITransport in client.go

## Question
Can a redirect followed by `newCAPITransport` in [pkg/cmd/agent-task/capi/client.go](pkg/cmd/agent-task/capi/client.go#L52) downgrade https to http (or to a non-HTTP scheme) while still sending credentials?

## Target
- File/function: [pkg/cmd/agent-task/capi/client.go:52](pkg/cmd/agent-task/capi/client.go#L52) - `newCAPITransport`
- Entrypoint: gh agent task
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Redirect to `http://collector/` and observe the token in cleartext.
- Invariant to test: Only https targets are followed; other schemes abort the request.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting an http:// Location produces an error and no request is sent.
