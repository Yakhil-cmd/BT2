# Q2349: ambiguous remote lets attacker choose the base repo - developRun in develop.go

## Question
Can an attacker-published repository's remotes cause `developRun` in [pkg/cmd/issue/develop/develop.go](pkg/cmd/issue/develop/develop.go#L167) to resolve a base repo the user does not expect, so subsequent authenticated writes (comments, PRs, secrets) go to attacker coordinates?

## Target
- File/function: [pkg/cmd/issue/develop/develop.go:167](pkg/cmd/issue/develop/develop.go#L167) - `developRun`
- Entrypoint: gh issue develop
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Ship a repo with `origin` pointing at the attacker fork.
- Invariant to test: Ambiguous resolution prompts or fails rather than silently choosing.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with competing remotes asserting the resolution.
