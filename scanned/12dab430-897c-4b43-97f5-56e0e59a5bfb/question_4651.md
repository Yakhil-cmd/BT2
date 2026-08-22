# Q4651: skill metadata trusted for later trust decisions - renderMarkdownPreview in preview.go

## Question
Does `renderMarkdownPreview` in [pkg/cmd/skills/preview/preview.go](pkg/cmd/skills/preview/preview.go#L392) persist skill-provided metadata that later code treats as gh-authoritative (source host, verified flag, permissions)?

## Target
- File/function: [pkg/cmd/skills/preview/preview.go:392](pkg/cmd/skills/preview/preview.go#L392) - `renderMarkdownPreview`
- Entrypoint: gh skills preview
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill claiming a trusted source in its own metadata.
- Invariant to test: Recorded provenance is written by gh from the validated request, never copied from content.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting recorded provenance for hostile metadata.
