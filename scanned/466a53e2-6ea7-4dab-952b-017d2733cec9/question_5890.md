# Q5890: host-scoped client leaked into another flow - fetchLatestRelease in http.go

## Question
Can the client/transport constructed in `fetchLatestRelease` in [pkg/cmd/extension/http.go](pkg/cmd/extension/http.go#L119) (with its auth round-tripper) be reused by a later flow whose target host came from an extension repository, its release assets, and its manifest fields?

## Target
- File/function: [pkg/cmd/extension/http.go:119](pkg/cmd/extension/http.go#L119) - `fetchLatestRelease`
- Entrypoint: gh extension http
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Chain two operations where the second targets an attacker host.
- Invariant to test: Auth round-trippers verify the request host on every call.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test reusing the client against a foreign host asserting the header is dropped.
