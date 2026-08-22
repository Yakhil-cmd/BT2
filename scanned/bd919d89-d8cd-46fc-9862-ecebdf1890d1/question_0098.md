# Q0098: host from override flag/env unchecked - NewWithHost in repo.go

## Question
Can a `-R OWNER/REPO`-style override or env-provided host flowing into `NewWithHost` in [internal/ghrepo/repo.go](internal/ghrepo/repo.go#L26) redirect authenticated traffic to an unauthenticated or attacker host?

## Target
- File/function: [internal/ghrepo/repo.go:26](internal/ghrepo/repo.go#L26) - `NewWithHost`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Get the victim to run a documented command form on attacker-supplied repo coordinates.
- Invariant to test: Overrides are parsed strictly and resolved against configured hosts before any request.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test of override strings asserting rejection of embedded hosts/URLs.
