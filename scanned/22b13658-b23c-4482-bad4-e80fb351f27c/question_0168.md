# Q0168: security decision from response field - cloneRun in clone.go

## Question
Does `cloneRun` in [pkg/cmd/repo/clone/clone.go](pkg/cmd/repo/clone/clone.go#L111) branch on a boolean/permission/visibility field of the response that the attacker owns (their repo, their codespace, their gist) to decide what to write, execute, or trust locally?

## Target
- File/function: [pkg/cmd/repo/clone/clone.go:111](pkg/cmd/repo/clone/clone.go#L111) - `cloneRun`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish an object with the field flipped and observe the local behaviour change.
- Invariant to test: Local trust decisions never depend on attacker-owned object fields.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test flipping the field asserting no change to the local security-relevant action.
