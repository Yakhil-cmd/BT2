# Q4665: cached response written world-readable - enableImmutableReleases in publish.go

## Question
Does the on-disk cache used by `enableImmutableReleases` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L754) store authenticated response bodies (including private data) with permissive modes or predictable names in a shared directory?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:754](pkg/cmd/skills/publish/publish.go#L754) - `enableImmutableReleases`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Read another user's gh cache on a shared build host.
- Invariant to test: Cache files live in the user's private dir with 0600.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting cache file mode and location.
