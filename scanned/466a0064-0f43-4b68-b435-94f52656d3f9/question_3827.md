# Q3827: cached response written world-readable - fetchReleaseFromTag in http.go

## Question
Does the on-disk cache used by `fetchReleaseFromTag` in [pkg/cmd/extension/http.go](pkg/cmd/extension/http.go#L147) store authenticated response bodies (including private data) with permissive modes or predictable names in a shared directory?

## Target
- File/function: [pkg/cmd/extension/http.go:147](pkg/cmd/extension/http.go#L147) - `fetchReleaseFromTag`
- Entrypoint: gh extension http
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Read another user's gh cache on a shared build host.
- Invariant to test: Cache files live in the user's private dir with 0600.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting cache file mode and location.
