# Q3013: credential helper answers for an attacker host - (Client).Clone in client.go

## Question
Can the git credential protocol handling in `Clone` in [git/client.go](git/client.go#L908) be induced to return the victim's GitHub token for a host or path the attacker chose?

## Target
- File/function: [git/client.go:908](git/client.go#L908) - `(Client).Clone`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a repo whose submodule or remote points at `github.com.evil.tld` and let git ask gh's helper for credentials.
- Invariant to test: The helper answers only for exactly-matching configured hosts.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Table test feeding helper stdin with lookalike hosts and asserting empty output.
