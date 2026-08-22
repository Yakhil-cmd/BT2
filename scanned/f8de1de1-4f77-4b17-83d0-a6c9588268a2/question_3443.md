# Q3443: refspec lets the server write local refs - (remoteGitClient).LastCommit in browse.go

## Question
Does the fetch performed in `LastCommit` in [pkg/cmd/browse/browse.go](pkg/cmd/browse/browse.go#L375) use a wildcard/attacker-influenced refspec so a hostile remote can create or overwrite local refs (including HEAD or a tracked branch)?

## Target
- File/function: [pkg/cmd/browse/browse.go:375](pkg/cmd/browse/browse.go#L375) - `(remoteGitClient).LastCommit`
- Entrypoint: gh browse browse
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Serve refs that map onto the victim's local branch names.
- Invariant to test: Fetches target explicit, gh-chosen ref destinations.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting the refspec is fixed and namespaced.
