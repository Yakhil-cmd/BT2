# Q4634: one-of-many bundle passes - filterHiddenDirSkills in install.go

## Question
When several bundles/attestations are supplied to `filterHiddenDirSkills` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L1266), can an attacker-added valid-but-irrelevant bundle satisfy the policy while the relevant one fails?

## Target
- File/function: [pkg/cmd/skills/install/install.go:1266](pkg/cmd/skills/install/install.go#L1266) - `filterHiddenDirSkills`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Attach a genuine bundle for an unrelated artifact next to the attacker's own.
- Invariant to test: Success requires a bundle that satisfies every policy predicate for this artifact.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with mixed bundles asserting failure unless a fully matching one exists.
