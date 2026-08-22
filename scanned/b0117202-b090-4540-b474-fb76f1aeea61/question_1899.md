# Q1899: cached response written world-readable - fetchDraftRelease in fetch.go

## Question
Does the on-disk cache used by `fetchDraftRelease` in [pkg/cmd/release/shared/fetch.go](pkg/cmd/release/shared/fetch.go#L246) store authenticated response bodies (including private data) with permissive modes or predictable names in a shared directory?

## Target
- File/function: [pkg/cmd/release/shared/fetch.go:246](pkg/cmd/release/shared/fetch.go#L246) - `fetchDraftRelease`
- Entrypoint: gh release
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Read another user's gh cache on a shared build host.
- Invariant to test: Cache files live in the user's private dir with 0600.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting cache file mode and location.
