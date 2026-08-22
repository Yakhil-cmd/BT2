# Q2196: credential helper answers for an attacker host - NewCmdToken in token.go

## Question
Can the git credential protocol handling in `NewCmdToken` in [pkg/cmd/auth/token/token.go](pkg/cmd/auth/token/token.go#L23) be induced to return the victim's GitHub token for a host or path the attacker chose?

## Target
- File/function: [pkg/cmd/auth/token/token.go:23](pkg/cmd/auth/token/token.go#L23) - `NewCmdToken`
- Entrypoint: gh auth token
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish a repo whose submodule or remote points at `github.com.evil.tld` and let git ask gh's helper for credentials.
- Invariant to test: The helper answers only for exactly-matching configured hosts.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Table test feeding helper stdin with lookalike hosts and asserting empty output.
