# Q0330: skill metadata trusted for later trust decisions - resolveRepoArg in install.go

## Question
Does `resolveRepoArg` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L580) persist skill-provided metadata that later code treats as gh-authoritative (source host, verified flag, permissions)?

## Target
- File/function: [pkg/cmd/skills/install/install.go:580](pkg/cmd/skills/install/install.go#L580) - `resolveRepoArg`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill claiming a trusted source in its own metadata.
- Invariant to test: Recorded provenance is written by gh from the validated request, never copied from content.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting recorded provenance for hostile metadata.
