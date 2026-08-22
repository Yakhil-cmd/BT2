# Q1927: client reuse leaks headers across hosts - NewCmdReadFile in read_file.go

## Question
Does `NewCmdReadFile` in [pkg/cmd/repo/read-file/read_file.go](pkg/cmd/repo/read-file/read_file.go#L51) reuse an HTTP client whose default headers were built for one host when issuing a request to a different host?

## Target
- File/function: [pkg/cmd/repo/read-file/read_file.go:51](pkg/cmd/repo/read-file/read_file.go#L51) - `NewCmdReadFile`
- Entrypoint: gh repo read-file
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Make one gh invocation touch both github.com and an attacker GHES host.
- Invariant to test: Auth headers are attached per-request after a host check, not baked into a shared client.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test issuing two requests on the same client to different hosts and asserting header isolation.
