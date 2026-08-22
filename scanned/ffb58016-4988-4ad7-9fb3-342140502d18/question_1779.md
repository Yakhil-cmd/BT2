# Q1779: empty result treated as success - filterHiddenDirSkills in install.go

## Question
If the attestation list, bundle set, or policy result reaching `filterHiddenDirSkills` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L1266) is empty or nil, does the code report success instead of failure?

## Target
- File/function: [pkg/cmd/skills/install/install.go:1266](pkg/cmd/skills/install/install.go#L1266) - `filterHiddenDirSkills`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Serve an empty attestations array from the API host for the attacker's artifact.
- Invariant to test: Zero verified attestations always yields a hard failure.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with an empty response asserting a non-zero exit and an error.
