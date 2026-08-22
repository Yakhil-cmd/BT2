# Q5754: refspec lets the server write local refs - (Updater).Update in updater.go

## Question
Does the fetch performed in `Update` in [pkg/cmd/auth/shared/gitcredentials/updater.go](pkg/cmd/auth/shared/gitcredentials/updater.go#L18) use a wildcard/attacker-influenced refspec so a hostile remote can create or overwrite local refs (including HEAD or a tracked branch)?

## Target
- File/function: [pkg/cmd/auth/shared/gitcredentials/updater.go:18](pkg/cmd/auth/shared/gitcredentials/updater.go#L18) - `(Updater).Update`
- Entrypoint: gh auth
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Serve refs that map onto the victim's local branch names.
- Invariant to test: Fetches target explicit, gh-chosen ref destinations.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting the refspec is fixed and namespaced.
