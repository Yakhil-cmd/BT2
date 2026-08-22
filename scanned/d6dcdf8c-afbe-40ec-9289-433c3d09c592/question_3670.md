# Q3670: type/absence confusion - FromFullNameWithHost in repo.go

## Question
If a field parsed in `FromFullNameWithHost` in [internal/ghrepo/repo.go](internal/ghrepo/repo.go#L52) is missing, null, or an unexpected type, does the zero value silently mean 'allowed', 'verified', or 'same host'?

## Target
- File/function: [internal/ghrepo/repo.go:52](internal/ghrepo/repo.go#L52) - `FromFullNameWithHost`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Omit the field from the attacker-served response.
- Invariant to test: Absent fields are distinguished from false/empty and fail closed.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with the field omitted asserting an explicit error.
