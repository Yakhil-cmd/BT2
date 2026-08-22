# Q4568: skill metadata trusted for later trust decisions - InstallLocal in installer.go

## Question
Does `InstallLocal` in [internal/skills/installer/installer.go](internal/skills/installer/installer.go#L156) persist skill-provided metadata that later code treats as gh-authoritative (source host, verified flag, permissions)?

## Target
- File/function: [internal/skills/installer/installer.go:156](internal/skills/installer/installer.go#L156) - `InstallLocal`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill claiming a trusted source in its own metadata.
- Invariant to test: Recorded provenance is written by gh from the validated request, never copied from content.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting recorded provenance for hostile metadata.
