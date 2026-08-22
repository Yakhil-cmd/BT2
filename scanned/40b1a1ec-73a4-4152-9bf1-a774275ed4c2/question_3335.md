# Q3335: unbounded response body - downloadAsset in download.go

## Question
Does `downloadAsset` in [pkg/cmd/release/download/download.go](pkg/cmd/release/download/download.go#L300) read the whole response body into memory without a limit, so an attacker-controlled endpoint can exhaust the victim's RAM?

## Target
- File/function: [pkg/cmd/release/download/download.go:300](pkg/cmd/release/download/download.go#L300) - `downloadAsset`
- Entrypoint: gh release download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Serve a multi-gigabyte body from an attacker-controlled host or asset URL.
- Invariant to test: Response reads are wrapped in a limit reader with an explicit cap.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with a huge/endless body asserting a bounded error.
