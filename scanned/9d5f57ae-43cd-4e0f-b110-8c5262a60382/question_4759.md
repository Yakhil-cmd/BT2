# Q4759: zip slip - checkArchiveTypeOption in download.go

## Question
Does `checkArchiveTypeOption` in [pkg/cmd/release/download/download.go](pkg/cmd/release/download/download.go#L123) trust the archive member name when extracting, so an entry named `../../.config/gh/hosts.yml` (or an absolute/UNC name) is written outside the destination?

## Target
- File/function: [pkg/cmd/release/download/download.go:123](pkg/cmd/release/download/download.go#L123) - `checkArchiveTypeOption`
- Entrypoint: gh release download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a workflow artifact / skill / extension archive containing a traversal entry, then let the victim run gh release download.
- Invariant to test: Extraction resolves each member against the destination and rejects anything escaping it.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test over crafted zips (`../`, `/etc/x`, `C:\`, `\\host\share`, backslash separators) asserting extraction fails.
