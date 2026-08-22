# Q0104: host taken from repo remote - (ghRepo).RepoHost in repo.go

## Question
Does `RepoHost` in [internal/ghrepo/repo.go](internal/ghrepo/repo.go#L119) accept the host embedded in a git remote URL of the repo the victim is standing in, without checking it against the authenticated hosts?

## Target
- File/function: [internal/ghrepo/repo.go:119](internal/ghrepo/repo.go#L119) - `(ghRepo).RepoHost`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish a repo whose `.git/config` remote (or submodule) points at an attacker host, then have the victim run any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...) inside a clone.
- Invariant to test: Hosts from repository metadata are only used after matching an authenticated host.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test in a temp repo with a hostile remote asserting gh refuses or does not authenticate.
