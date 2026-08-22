# Q3022: client reuse leaks headers across hosts - NewRemote in objects.go

## Question
Does `NewRemote` in [git/objects.go](git/objects.go#L42) reuse an HTTP client whose default headers were built for one host when issuing a request to a different host?

## Target
- File/function: [git/objects.go:42](git/objects.go#L42) - `NewRemote`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Make one gh invocation touch both github.com and an attacker GHES host.
- Invariant to test: Auth headers are attached per-request after a host check, not baked into a shared client.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test issuing two requests on the same client to different hosts and asserting header isolation.
