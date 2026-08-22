# Q5375: skill metadata trusted for later trust decisions - detectDefaultBranch in publish.go

## Question
Does `detectDefaultBranch` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L690) persist skill-provided metadata that later code treats as gh-authoritative (source host, verified flag, permissions)?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:690](pkg/cmd/skills/publish/publish.go#L690) - `detectDefaultBranch`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill claiming a trusted source in its own metadata.
- Invariant to test: Recorded provenance is written by gh from the validated request, never copied from content.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting recorded provenance for hostile metadata.
