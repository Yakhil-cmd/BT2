# Q2812: token attached to non-matching host - (capiTransport).RoundTrip in client.go

## Question
Can `RoundTrip` in [pkg/cmd/agent-task/capi/client.go](pkg/cmd/agent-task/capi/client.go#L64) attach the token stored for one host to a request whose host was derived from an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes?

## Target
- File/function: [pkg/cmd/agent-task/capi/client.go:64](pkg/cmd/agent-task/capi/client.go#L64) - `(capiTransport).RoundTrip`
- Entrypoint: gh agent task
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish a repo/remote that resolves to a host the attacker controls while the victim's active token is for github.com.
- Invariant to test: A token is only ever sent to the exact host it was issued for.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Unit test with two configured hosts asserting the header matches the request host.
