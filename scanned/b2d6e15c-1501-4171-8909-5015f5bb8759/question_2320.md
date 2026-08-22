# Q2320: security decision from response field - syncRemoteRepo in sync.go

## Question
Does `syncRemoteRepo` in [pkg/cmd/repo/sync/sync.go](pkg/cmd/repo/sync/sync.go#L168) branch on a boolean/permission/visibility field of the response that the attacker owns (their repo, their codespace, their gist) to decide what to write, execute, or trust locally?

## Target
- File/function: [pkg/cmd/repo/sync/sync.go:168](pkg/cmd/repo/sync/sync.go#L168) - `syncRemoteRepo`
- Entrypoint: gh repo sync
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish an object with the field flipped and observe the local behaviour change.
- Invariant to test: Local trust decisions never depend on attacker-owned object fields.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test flipping the field asserting no change to the local security-relevant action.
