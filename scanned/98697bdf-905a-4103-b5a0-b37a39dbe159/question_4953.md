# Q4953: credential helper answers for an attacker host - (capiTransport).RoundTrip in client.go

## Question
Can the git credential protocol handling in `RoundTrip` in [pkg/cmd/agent-task/capi/client.go](pkg/cmd/agent-task/capi/client.go#L64) be induced to return the victim's GitHub token for a host or path the attacker chose?

## Target
- File/function: [pkg/cmd/agent-task/capi/client.go:64](pkg/cmd/agent-task/capi/client.go#L64) - `(capiTransport).RoundTrip`
- Entrypoint: gh agent task
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish a repo whose submodule or remote points at `github.com.evil.tld` and let git ask gh's helper for credentials.
- Invariant to test: The helper answers only for exactly-matching configured hosts.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Table test feeding helper stdin with lookalike hosts and asserting empty output.
