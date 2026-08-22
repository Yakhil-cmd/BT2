# Q2613: case, trailing dot, and IDN normalization - fetchDraftRelease in fetch.go

## Question
Can `fetchDraftRelease` in [pkg/cmd/release/shared/fetch.go](pkg/cmd/release/shared/fetch.go#L246) be fed `GitHub.com.`, an IDN homograph, or a percent-encoded host that normalizes differently for the trust check than for the connection?

## Target
- File/function: [pkg/cmd/release/shared/fetch.go:246](pkg/cmd/release/shared/fetch.go#L246) - `fetchDraftRelease`
- Entrypoint: gh release
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Use a trailing-dot or unicode variant in a remote URL so validation and dialing disagree.
- Invariant to test: Hostnames are lowercased, punycode-normalized, and dot-trimmed once, before both use sites.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Fuzz host strings asserting normalize(validate(h)) == host used to dial.
