# Q0863: refspec lets the server write local refs - (RemoteTrackingRef).String in client.go

## Question
Does the fetch performed in `String` in [git/client.go](git/client.go#L563) use a wildcard/attacker-influenced refspec so a hostile remote can create or overwrite local refs (including HEAD or a tracked branch)?

## Target
- File/function: [git/client.go:563](git/client.go#L563) - `(RemoteTrackingRef).String`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Serve refs that map onto the victim's local branch names.
- Invariant to test: Fetches target explicit, gh-chosen ref destinations.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting the refspec is fixed and namespaced.
