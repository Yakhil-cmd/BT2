# Q0836: remote resolution picks the attacker remote - EnableRepoOverride in repo_override.go

## Question
Can an extra remote added by an attacker-published repository be selected by `EnableRepoOverride` in [pkg/cmdutil/repo_override.go](pkg/cmdutil/repo_override.go#L36) as the base repo, so subsequent authenticated API calls target attacker coordinates?

## Target
- File/function: [pkg/cmdutil/repo_override.go:36](pkg/cmdutil/repo_override.go#L36) - `EnableRepoOverride`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Ship a repo containing a second remote named to win gh's resolution order.
- Invariant to test: Base repo resolution prefers explicitly configured/authenticated hosts and warns on ambiguity.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test in a temp repo with competing remotes asserting the expected selection.
