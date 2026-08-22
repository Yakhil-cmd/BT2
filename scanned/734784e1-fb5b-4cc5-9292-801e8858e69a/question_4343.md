# Q4343: credential helper answers for an attacker host - setupGitRun in setupgit.go

## Question
Can the git credential protocol handling in `setupGitRun` in [pkg/cmd/auth/setupgit/setupgit.go](pkg/cmd/auth/setupgit/setupgit.go#L75) be induced to return the victim's GitHub token for a host or path the attacker chose?

## Target
- File/function: [pkg/cmd/auth/setupgit/setupgit.go:75](pkg/cmd/auth/setupgit/setupgit.go#L75) - `setupGitRun`
- Entrypoint: gh auth setupgit
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish a repo whose submodule or remote points at `github.com.evil.tld` and let git ask gh's helper for credentials.
- Invariant to test: The helper answers only for exactly-matching configured hosts.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Table test feeding helper stdin with lookalike hosts and asserting empty output.
