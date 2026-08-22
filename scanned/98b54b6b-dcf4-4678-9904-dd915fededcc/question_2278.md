# Q2278: ambiguous remote lets attacker choose the base repo - CredentialPatternFromGitURL in client.go

## Question
Can an attacker-published repository's remotes cause `CredentialPatternFromGitURL` in [git/client.go](git/client.go#L123) to resolve a base repo the user does not expect, so subsequent authenticated writes (comments, PRs, secrets) go to attacker coordinates?

## Target
- File/function: [git/client.go:123](git/client.go#L123) - `CredentialPatternFromGitURL`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Ship a repo with `origin` pointing at the attacker fork.
- Invariant to test: Ambiguous resolution prompts or fails rather than silently choosing.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with competing remotes asserting the resolution.
