# Q1526: empty/default host fallback - NewWithHost in repo.go

## Question
When host resolution fails inside `NewWithHost` in [internal/ghrepo/repo.go](internal/ghrepo/repo.go#L26), does it silently fall back to the default host (or the first configured account) and use those credentials for attacker-chosen coordinates?

## Target
- File/function: [internal/ghrepo/repo.go:26](internal/ghrepo/repo.go#L26) - `NewWithHost`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Make host resolution fail on an attacker-published repo and observe which token is used.
- Invariant to test: Failed resolution aborts; no implicit credential selection.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with an unresolvable host asserting an error rather than a default token.
