# Q3111: client reuse leaks headers across hosts - downloadAsset in http.go

## Question
Does `downloadAsset` in [pkg/cmd/extension/http.go](pkg/cmd/extension/http.go#L79) reuse an HTTP client whose default headers were built for one host when issuing a request to a different host?

## Target
- File/function: [pkg/cmd/extension/http.go:79](pkg/cmd/extension/http.go#L79) - `downloadAsset`
- Entrypoint: gh extension http
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Make one gh invocation touch both github.com and an attacker GHES host.
- Invariant to test: Auth headers are attached per-request after a host check, not baked into a shared client.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test issuing two requests on the same client to different hosts and asserting header isolation.
