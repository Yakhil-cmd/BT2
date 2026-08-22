# Q3746: git version/feature probe drives an unsafe fallback - NewCmdSync in sync.go

## Question
Does `NewCmdSync` in [pkg/cmd/repo/sync/sync.go](pkg/cmd/repo/sync/sync.go#L36) fall back to a less safe git invocation when a probe fails, in a way an attacker-published repository can force?

## Target
- File/function: [pkg/cmd/repo/sync/sync.go:36](pkg/cmd/repo/sync/sync.go#L36) - `NewCmdSync`
- Entrypoint: gh repo sync
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Make the probe fail via repository state, then observe the fallback argv.
- Invariant to test: Fallbacks preserve every safety property of the primary path.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test forcing the probe failure asserting the fallback argv is still safe.
