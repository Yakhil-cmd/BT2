# Q0203: security decision from response field - preloadPrChecks in finder.go

## Question
Does `preloadPrChecks` in [pkg/cmd/pr/shared/finder.go](pkg/cmd/pr/shared/finder.go#L563) branch on a boolean/permission/visibility field of the response that the attacker owns (their repo, their codespace, their gist) to decide what to write, execute, or trust locally?

## Target
- File/function: [pkg/cmd/pr/shared/finder.go:563](pkg/cmd/pr/shared/finder.go#L563) - `preloadPrChecks`
- Entrypoint: gh pr
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish an object with the field flipped and observe the local behaviour change.
- Invariant to test: Local trust decisions never depend on attacker-owned object fields.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test flipping the field asserting no change to the local security-relevant action.
