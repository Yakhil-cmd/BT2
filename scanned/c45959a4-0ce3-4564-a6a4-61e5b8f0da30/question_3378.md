# Q3378: client reuse leaks headers across hosts - createGist in create.go

## Question
Does `createGist` in [pkg/cmd/gist/create/create.go](pkg/cmd/gist/create/create.go#L263) reuse an HTTP client whose default headers were built for one host when issuing a request to a different host?

## Target
- File/function: [pkg/cmd/gist/create/create.go:263](pkg/cmd/gist/create/create.go#L263) - `createGist`
- Entrypoint: gh gist create
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Make one gh invocation touch both github.com and an attacker GHES host.
- Invariant to test: Auth headers are attached per-request after a host check, not baked into a shared client.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test issuing two requests on the same client to different hosts and asserting header isolation.
