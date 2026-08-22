# Q3219: cached response written world-readable - previewRun in preview.go

## Question
Does the on-disk cache used by `previewRun` in [pkg/cmd/skills/preview/preview.go](pkg/cmd/skills/preview/preview.go#L128) store authenticated response bodies (including private data) with permissive modes or predictable names in a shared directory?

## Target
- File/function: [pkg/cmd/skills/preview/preview.go:128](pkg/cmd/skills/preview/preview.go#L128) - `previewRun`
- Entrypoint: gh skills preview
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Read another user's gh cache on a shared build host.
- Invariant to test: Cache files live in the user's private dir with 0600.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting cache file mode and location.
