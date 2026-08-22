# Q5109: refspec lets the server write local refs - remotesFunc in default.go

## Question
Does the fetch performed in `remotesFunc` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L178) use a wildcard/attacker-influenced refspec so a hostile remote can create or overwrite local refs (including HEAD or a tracked branch)?

## Target
- File/function: [pkg/cmd/factory/default.go:178](pkg/cmd/factory/default.go#L178) - `remotesFunc`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Serve refs that map onto the victim's local branch names.
- Invariant to test: Fetches target explicit, gh-chosen ref destinations.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting the refspec is fixed and namespaced.
