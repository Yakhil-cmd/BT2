# Q3212: skill metadata trusted for later trust decisions - swapDirectoryContents in update.go

## Question
Does `swapDirectoryContents` in [pkg/cmd/skills/update/update.go](pkg/cmd/skills/update/update.go#L470) persist skill-provided metadata that later code treats as gh-authoritative (source host, verified flag, permissions)?

## Target
- File/function: [pkg/cmd/skills/update/update.go:470](pkg/cmd/skills/update/update.go#L470) - `swapDirectoryContents`
- Entrypoint: gh skills update
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill claiming a trusted source in its own metadata.
- Invariant to test: Recorded provenance is written by gh from the validated request, never copied from content.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting recorded provenance for hostile metadata.
