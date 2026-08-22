# Q5014: credential helper answers for an attacker host - (AuthConfig).HasActiveToken in config.go

## Question
Can the git credential protocol handling in `HasActiveToken` in [internal/config/config.go](internal/config/config.go#L263) be induced to return the victim's GitHub token for a host or path the attacker chose?

## Target
- File/function: [internal/config/config.go:263](internal/config/config.go#L263) - `(AuthConfig).HasActiveToken`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish a repo whose submodule or remote points at `github.com.evil.tld` and let git ask gh's helper for credentials.
- Invariant to test: The helper answers only for exactly-matching configured hosts.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Table test feeding helper stdin with lookalike hosts and asserting empty output.
