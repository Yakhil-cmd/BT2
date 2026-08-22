# Q1626: git version/feature probe drives an unsafe fallback - findByNumber in finder.go

## Question
Does `findByNumber` in [pkg/cmd/pr/shared/finder.go](pkg/cmd/pr/shared/finder.go#L356) fall back to a less safe git invocation when a probe fails, in a way an attacker-published repository can force?

## Target
- File/function: [pkg/cmd/pr/shared/finder.go:356](pkg/cmd/pr/shared/finder.go#L356) - `findByNumber`
- Entrypoint: gh pr
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Make the probe fail via repository state, then observe the fallback argv.
- Invariant to test: Fallbacks preserve every safety property of the primary path.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test forcing the probe failure asserting the fallback argv is still safe.
