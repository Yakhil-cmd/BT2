# Q3009: client reuse leaks headers across hosts - (Client).AddRemote in client.go

## Question
Does `AddRemote` in [git/client.go](git/client.go#L831) reuse an HTTP client whose default headers were built for one host when issuing a request to a different host?

## Target
- File/function: [git/client.go:831](git/client.go#L831) - `(Client).AddRemote`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Make one gh invocation touch both github.com and an attacker GHES host.
- Invariant to test: Auth headers are attached per-request after a host check, not baked into a shared client.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test issuing two requests on the same client to different hosts and asserting header isolation.
