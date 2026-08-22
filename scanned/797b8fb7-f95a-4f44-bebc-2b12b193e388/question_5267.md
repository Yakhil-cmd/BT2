# Q5267: type/absence confusion - expandAlias in alias.go

## Question
If a field parsed in `expandAlias` in [pkg/cmd/root/alias.go](pkg/cmd/root/alias.go#L79) is missing, null, or an unexpected type, does the zero value silently mean 'allowed', 'verified', or 'same host'?

## Target
- File/function: [pkg/cmd/root/alias.go:79](pkg/cmd/root/alias.go#L79) - `expandAlias`
- Entrypoint: gh root alias
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Omit the field from the attacker-served response.
- Invariant to test: Absent fields are distinguished from false/empty and fail closed.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with the field omitted asserting an explicit error.
