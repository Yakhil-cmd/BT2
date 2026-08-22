# Q2668: type/absence confusion - (Untrusted).UnmarshalJSON in untrusted.go

## Question
If a field parsed in `UnmarshalJSON` in [pkg/iostreams/untrusted.go](pkg/iostreams/untrusted.go#L63) is missing, null, or an unexpected type, does the zero value silently mean 'allowed', 'verified', or 'same host'?

## Target
- File/function: [pkg/iostreams/untrusted.go:63](pkg/iostreams/untrusted.go#L63) - `(Untrusted).UnmarshalJSON`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Omit the field from the attacker-served response.
- Invariant to test: Absent fields are distinguished from false/empty and fail closed.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with the field omitted asserting an explicit error.
