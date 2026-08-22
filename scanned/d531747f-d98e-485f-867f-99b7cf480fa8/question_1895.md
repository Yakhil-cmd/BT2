# Q1895: zip slip - FetchRefSHA in fetch.go

## Question
Does `FetchRefSHA` in [pkg/cmd/release/shared/fetch.go](pkg/cmd/release/shared/fetch.go#L140) trust the archive member name when extracting, so an entry named `../../.config/gh/hosts.yml` (or an absolute/UNC name) is written outside the destination?

## Target
- File/function: [pkg/cmd/release/shared/fetch.go:140](pkg/cmd/release/shared/fetch.go#L140) - `FetchRefSHA`
- Entrypoint: gh release
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a workflow artifact / skill / extension archive containing a traversal entry, then let the victim run gh release.
- Invariant to test: Extraction resolves each member against the destination and rejects anything escaping it.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test over crafted zips (`../`, `/etc/x`, `C:\`, `\\host\share`, backslash separators) asserting extraction fails.
