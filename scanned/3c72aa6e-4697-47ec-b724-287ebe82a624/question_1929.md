# Q1929: host-scoped client leaked into another flow - loadContent in read_file.go

## Question
Can the client/transport constructed in `loadContent` in [pkg/cmd/repo/read-file/read_file.go](pkg/cmd/repo/read-file/read_file.go#L216) (with its auth round-tripper) be reused by a later flow whose target host came from an asset, artifact, gist, or archive-member name and its bytes?

## Target
- File/function: [pkg/cmd/repo/read-file/read_file.go:216](pkg/cmd/repo/read-file/read_file.go#L216) - `loadContent`
- Entrypoint: gh repo read-file
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Chain two operations where the second targets an attacker host.
- Invariant to test: Auth round-trippers verify the request host on every call.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test reusing the client against a foreign host asserting the header is dropped.
