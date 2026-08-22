# Q3233: skill metadata trusted for later trust decisions - runPublishRelease in publish.go

## Question
Does `runPublishRelease` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L481) persist skill-provided metadata that later code treats as gh-authoritative (source host, verified flag, permissions)?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:481](pkg/cmd/skills/publish/publish.go#L481) - `runPublishRelease`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill claiming a trusted source in its own metadata.
- Invariant to test: Recorded provenance is written by gh from the validated request, never copied from content.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting recorded provenance for hostile metadata.
