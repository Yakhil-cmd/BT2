# Q2465: skill metadata trusted for later trust decisions - DiscoverLocalSkills in discovery.go

## Question
Does `DiscoverLocalSkills` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L950) persist skill-provided metadata that later code treats as gh-authoritative (source host, verified flag, permissions)?

## Target
- File/function: [internal/skills/discovery/discovery.go:950](internal/skills/discovery/discovery.go#L950) - `DiscoverLocalSkills`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill claiming a trusted source in its own metadata.
- Invariant to test: Recorded provenance is written by gh from the validated request, never copied from content.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting recorded provenance for hostile metadata.
