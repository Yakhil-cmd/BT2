# Q3226: skill metadata trusted for later trust decisions - selectSkill in preview.go

## Question
Does `selectSkill` in [pkg/cmd/skills/preview/preview.go](pkg/cmd/skills/preview/preview.go#L453) persist skill-provided metadata that later code treats as gh-authoritative (source host, verified flag, permissions)?

## Target
- File/function: [pkg/cmd/skills/preview/preview.go:453](pkg/cmd/skills/preview/preview.go#L453) - `selectSkill`
- Entrypoint: gh skills preview
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill claiming a trusted source in its own metadata.
- Invariant to test: Recorded provenance is written by gh from the validated request, never copied from content.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting recorded provenance for hostile metadata.
