# Q0328: cached response written world-readable - installRun in install.go

## Question
Does the on-disk cache used by `installRun` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L255) store authenticated response bodies (including private data) with permissive modes or predictable names in a shared directory?

## Target
- File/function: [pkg/cmd/skills/install/install.go:255](pkg/cmd/skills/install/install.go#L255) - `installRun`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Read another user's gh cache on a shared build host.
- Invariant to test: Cache files live in the user's private dir with 0600.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting cache file mode and location.
