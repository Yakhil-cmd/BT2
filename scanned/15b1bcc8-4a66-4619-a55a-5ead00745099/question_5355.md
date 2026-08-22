# Q5355: skill metadata trusted for later trust decisions - scanInstalledSkills in update.go

## Question
Does `scanInstalledSkills` in [pkg/cmd/skills/update/update.go](pkg/cmd/skills/update/update.go#L554) persist skill-provided metadata that later code treats as gh-authoritative (source host, verified flag, permissions)?

## Target
- File/function: [pkg/cmd/skills/update/update.go:554](pkg/cmd/skills/update/update.go#L554) - `scanInstalledSkills`
- Entrypoint: gh skills update
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill claiming a trusted source in its own metadata.
- Invariant to test: Recorded provenance is written by gh from the validated request, never copied from content.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting recorded provenance for hostile metadata.
