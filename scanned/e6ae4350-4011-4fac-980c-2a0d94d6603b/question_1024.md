# Q1024: cached response written world-readable - resolveDefaultBranch in discovery.go

## Question
Does the on-disk cache used by `resolveDefaultBranch` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L366) store authenticated response bodies (including private data) with permissive modes or predictable names in a shared directory?

## Target
- File/function: [internal/skills/discovery/discovery.go:366](internal/skills/discovery/discovery.go#L366) - `resolveDefaultBranch`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Read another user's gh cache on a shared build host.
- Invariant to test: Cache files live in the user's private dir with 0600.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting cache file mode and location.
