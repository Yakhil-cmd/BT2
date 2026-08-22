# Q3744: remote resolution picks the attacker remote - (gitExecuter).CurrentBranch in git.go

## Question
Can an extra remote added by an attacker-published repository be selected by `CurrentBranch` in [pkg/cmd/repo/sync/git.go](pkg/cmd/repo/sync/git.go#L52) as the base repo, so subsequent authenticated API calls target attacker coordinates?

## Target
- File/function: [pkg/cmd/repo/sync/git.go:52](pkg/cmd/repo/sync/git.go#L52) - `(gitExecuter).CurrentBranch`
- Entrypoint: gh repo sync
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Ship a repo containing a second remote named to win gh's resolution order.
- Invariant to test: Base repo resolution prefers explicitly configured/authenticated hosts and warns on ambiguity.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test in a temp repo with competing remotes asserting the expected selection.
