# Q5058: client reuse leaks headers across hosts - helperRun in helper.go

## Question
Does `helperRun` in [pkg/cmd/auth/gitcredential/helper.go](pkg/cmd/auth/gitcredential/helper.go#L58) reuse an HTTP client whose default headers were built for one host when issuing a request to a different host?

## Target
- File/function: [pkg/cmd/auth/gitcredential/helper.go:58](pkg/cmd/auth/gitcredential/helper.go#L58) - `helperRun`
- Entrypoint: gh auth gitcredential
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Make one gh invocation touch both github.com and an attacker GHES host.
- Invariant to test: Auth headers are attached per-request after a host check, not baked into a shared client.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test issuing two requests on the same client to different hosts and asserting header isolation.
