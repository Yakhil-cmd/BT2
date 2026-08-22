# Q5979: type/absence confusion - parseInstalledSkill in update.go

## Question
If a field parsed in `parseInstalledSkill` in [pkg/cmd/skills/update/update.go](pkg/cmd/skills/update/update.go#L601) is missing, null, or an unexpected type, does the zero value silently mean 'allowed', 'verified', or 'same host'?

## Target
- File/function: [pkg/cmd/skills/update/update.go:601](pkg/cmd/skills/update/update.go#L601) - `parseInstalledSkill`
- Entrypoint: gh skills update
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Omit the field from the attacker-served response.
- Invariant to test: Absent fields are distinguished from false/empty and fail closed.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with the field omitted asserting an explicit error.
