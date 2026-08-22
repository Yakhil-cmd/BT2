# Q2302: type/absence confusion - parseRemoteURLOrName in client.go

## Question
If a field parsed in `parseRemoteURLOrName` in [git/client.go](git/client.go#L1026) is missing, null, or an unexpected type, does the zero value silently mean 'allowed', 'verified', or 'same host'?

## Target
- File/function: [git/client.go:1026](git/client.go#L1026) - `parseRemoteURLOrName`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Omit the field from the attacker-served response.
- Invariant to test: Absent fields are distinguished from false/empty and fail closed.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with the field omitted asserting an explicit error.
