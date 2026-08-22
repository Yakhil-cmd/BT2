# Q4532: refspec lets the server write local refs - (gitExecuter).CheckoutBranch in git.go

## Question
Does the fetch performed in `CheckoutBranch` in [pkg/cmd/extension/git.go](pkg/cmd/extension/git.go#L24) use a wildcard/attacker-influenced refspec so a hostile remote can create or overwrite local refs (including HEAD or a tracked branch)?

## Target
- File/function: [pkg/cmd/extension/git.go:24](pkg/cmd/extension/git.go#L24) - `(gitExecuter).CheckoutBranch`
- Entrypoint: gh extension git
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Serve refs that map onto the victim's local branch names.
- Invariant to test: Fetches target explicit, gh-chosen ref destinations.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting the refspec is fixed and namespaced.
