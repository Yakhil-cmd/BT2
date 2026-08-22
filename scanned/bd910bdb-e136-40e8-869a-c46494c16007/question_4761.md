# Q4761: cached response written world-readable - downloadAssets in download.go

## Question
Does the on-disk cache used by `downloadAssets` in [pkg/cmd/release/download/download.go](pkg/cmd/release/download/download.go#L262) store authenticated response bodies (including private data) with permissive modes or predictable names in a shared directory?

## Target
- File/function: [pkg/cmd/release/download/download.go:262](pkg/cmd/release/download/download.go#L262) - `downloadAssets`
- Entrypoint: gh release download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Read another user's gh cache on a shared build host.
- Invariant to test: Cache files live in the user's private dir with 0600.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting cache file mode and location.
