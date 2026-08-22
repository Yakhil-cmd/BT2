# Q5246: remote resolution picks the attacker remote - (gitExecuter).Clone in git.go

## Question
Can an extra remote added by an attacker-published repository be selected by `Clone` in [pkg/cmd/extension/git.go](pkg/cmd/extension/git.go#L28) as the base repo, so subsequent authenticated API calls target attacker coordinates?

## Target
- File/function: [pkg/cmd/extension/git.go:28](pkg/cmd/extension/git.go#L28) - `(gitExecuter).Clone`
- Entrypoint: gh extension git
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Ship a repo containing a second remote named to win gh's resolution order.
- Invariant to test: Base repo resolution prefers explicitly configured/authenticated hosts and warns on ambiguity.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test in a temp repo with competing remotes asserting the expected selection.
