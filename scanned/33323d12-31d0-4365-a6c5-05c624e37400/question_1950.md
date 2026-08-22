# Q1950: host-scoped client leaked into another flow - createGist in create.go

## Question
Can the client/transport constructed in `createGist` in [pkg/cmd/gist/create/create.go](pkg/cmd/gist/create/create.go#L263) (with its auth round-tripper) be reused by a later flow whose target host came from an asset, artifact, gist, or archive-member name and its bytes?

## Target
- File/function: [pkg/cmd/gist/create/create.go:263](pkg/cmd/gist/create/create.go#L263) - `createGist`
- Entrypoint: gh gist create
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Chain two operations where the second targets an attacker host.
- Invariant to test: Auth round-trippers verify the request host on every call.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test reusing the client against a foreign host asserting the header is dropped.
