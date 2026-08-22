# Q0102: enterprise/dotcom misclassification - IsSame in repo.go

## Question
Can a repo/remote/host string or API response field the attacker publishes make `IsSame` in [internal/ghrepo/repo.go](internal/ghrepo/repo.go#L79) misclassify a host as enterprise or dotcom, selecting different API base paths, auth rules, or feature gates than the user intends?

## Target
- File/function: [internal/ghrepo/repo.go:79](internal/ghrepo/repo.go#L79) - `IsSame`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish a remote whose host triggers the wrong branch and observe the relaxed path.
- Invariant to test: Classification derives from the exact configured host with no remote input.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test asserting classification for lookalike and mixed-case hosts.
