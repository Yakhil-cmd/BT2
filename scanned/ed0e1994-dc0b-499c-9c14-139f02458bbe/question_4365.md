# Q4365: credential helper answers for an attacker host - NewHTTPClient in http_client.go

## Question
Can the git credential protocol handling in `NewHTTPClient` in [api/http_client.go](api/http_client.go#L33) be induced to return the victim's GitHub token for a host or path the attacker chose?

## Target
- File/function: [api/http_client.go:33](api/http_client.go#L33) - `NewHTTPClient`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish a repo whose submodule or remote points at `github.com.evil.tld` and let git ask gh's helper for credentials.
- Invariant to test: The helper answers only for exactly-matching configured hosts.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Table test feeding helper stdin with lookalike hosts and asserting empty output.
