# Q3939: policy fields default to permissive - filterHiddenDirSkills in preview.go

## Question
Do unset or unparsed policy fields in `filterHiddenDirSkills` in [pkg/cmd/skills/preview/preview.go](pkg/cmd/skills/preview/preview.go#L423) default to matching everything (empty string, nil regex, zero value) rather than failing closed?

## Target
- File/function: [pkg/cmd/skills/preview/preview.go:423](pkg/cmd/skills/preview/preview.go#L423) - `filterHiddenDirSkills`
- Entrypoint: gh skills preview
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Supply a bundle lacking the extension the policy checks.
- Invariant to test: Missing policy inputs fail closed.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Unit test constructing a policy with zero-value fields asserting no artifact verifies.
