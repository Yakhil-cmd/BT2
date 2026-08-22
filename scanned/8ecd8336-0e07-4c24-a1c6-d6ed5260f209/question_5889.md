# Q5889: binary extension asset path/name unvalidated - downloadAsset in http.go

## Question
Does `downloadAsset` in [pkg/cmd/extension/http.go](pkg/cmd/extension/http.go#L79) use the release asset name or manifest field from the extension repository as the local filename or executable path?

## Target
- File/function: [pkg/cmd/extension/http.go:79](pkg/cmd/extension/http.go#L79) - `downloadAsset`
- Entrypoint: gh extension http
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish a release whose asset name contains traversal or targets an existing binary.
- Invariant to test: Local names are derived from the extension name gh computed, not from remote fields.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test with hostile asset names asserting the written path.
