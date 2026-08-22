# Q2753: credential helper answers for an attacker host - connect in invoker.go

## Question
Can the git credential protocol handling in `connect` in [internal/codespaces/rpc/invoker.go](internal/codespaces/rpc/invoker.go#L77) be induced to return the victim's GitHub token for a host or path the attacker chose?

## Target
- File/function: [internal/codespaces/rpc/invoker.go:77](internal/codespaces/rpc/invoker.go#L77) - `connect`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a repo whose submodule or remote points at `github.com.evil.tld` and let git ask gh's helper for credentials.
- Invariant to test: The helper answers only for exactly-matching configured hosts.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Table test feeding helper stdin with lookalike hosts and asserting empty output.
