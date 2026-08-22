# Q4451: refspec lets the server write local refs - NewCmdClone in clone.go

## Question
Does the fetch performed in `NewCmdClone` in [pkg/cmd/repo/clone/clone.go](pkg/cmd/repo/clone/clone.go#L33) use a wildcard/attacker-influenced refspec so a hostile remote can create or overwrite local refs (including HEAD or a tracked branch)?

## Target
- File/function: [pkg/cmd/repo/clone/clone.go:33](pkg/cmd/repo/clone/clone.go#L33) - `NewCmdClone`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Serve refs that map onto the victim's local branch names.
- Invariant to test: Fetches target explicit, gh-chosen ref destinations.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting the refspec is fixed and namespaced.
