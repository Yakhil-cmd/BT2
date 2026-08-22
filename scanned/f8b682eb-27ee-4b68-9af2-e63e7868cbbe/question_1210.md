# Q1210: type/absence confusion - truncateAsUTF16 in logs.go

## Question
If a field parsed in `truncateAsUTF16` in [pkg/cmd/run/view/logs.go](pkg/cmd/run/view/logs.go#L342) is missing, null, or an unexpected type, does the zero value silently mean 'allowed', 'verified', or 'same host'?

## Target
- File/function: [pkg/cmd/run/view/logs.go:342](pkg/cmd/run/view/logs.go#L342) - `truncateAsUTF16`
- Entrypoint: gh run view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Omit the field from the attacker-served response.
- Invariant to test: Absent fields are distinguished from false/empty and fail closed.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with the field omitted asserting an explicit error.
