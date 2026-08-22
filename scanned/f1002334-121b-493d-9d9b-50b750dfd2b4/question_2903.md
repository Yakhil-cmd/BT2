# Q2903: refspec lets the server write local refs - NewCmdLogin in login.go

## Question
Does the fetch performed in `NewCmdLogin` in [pkg/cmd/auth/login/login.go](pkg/cmd/auth/login/login.go#L45) use a wildcard/attacker-influenced refspec so a hostile remote can create or overwrite local refs (including HEAD or a tracked branch)?

## Target
- File/function: [pkg/cmd/auth/login/login.go:45](pkg/cmd/auth/login/login.go#L45) - `NewCmdLogin`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Serve refs that map onto the victim's local branch names.
- Invariant to test: Fetches target explicit, gh-chosen ref destinations.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting the refspec is fixed and namespaced.
