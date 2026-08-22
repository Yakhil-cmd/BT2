# Q1601: ambiguous remote lets attacker choose the base repo - (gitExecuter).CreateBranch in git.go

## Question
Can an attacker-published repository's remotes cause `CreateBranch` in [pkg/cmd/repo/sync/git.go](pkg/cmd/repo/sync/git.go#L35) to resolve a base repo the user does not expect, so subsequent authenticated writes (comments, PRs, secrets) go to attacker coordinates?

## Target
- File/function: [pkg/cmd/repo/sync/git.go:35](pkg/cmd/repo/sync/git.go#L35) - `(gitExecuter).CreateBranch`
- Entrypoint: gh repo sync
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Ship a repo with `origin` pointing at the attacker fork.
- Invariant to test: Ambiguous resolution prompts or fails rather than silently choosing.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with competing remotes asserting the resolution.
