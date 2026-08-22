# Q1010: type/absence confusion - readFrom in lockfile.go

## Question
If a field parsed in `readFrom` in [internal/skills/lockfile/lockfile.go](internal/skills/lockfile/lockfile.go#L53) is missing, null, or an unexpected type, does the zero value silently mean 'allowed', 'verified', or 'same host'?

## Target
- File/function: [internal/skills/lockfile/lockfile.go:53](internal/skills/lockfile/lockfile.go#L53) - `readFrom`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Omit the field from the attacker-served response.
- Invariant to test: Absent fields are distinguished from false/empty and fail closed.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with the field omitted asserting an explicit error.
