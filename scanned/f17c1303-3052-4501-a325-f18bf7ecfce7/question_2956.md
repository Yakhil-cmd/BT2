# Q2956: hostile JSON drives a security decision - FromFullNameWithHost in repo.go

## Question
Does `FromFullNameWithHost` in [internal/ghrepo/repo.go](internal/ghrepo/repo.go#L52) unmarshal a response field that later gates a security decision (host, path, permission, verification result) without validating its shape or range?

## Target
- File/function: [internal/ghrepo/repo.go:52](internal/ghrepo/repo.go#L52) - `FromFullNameWithHost`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Return a crafted JSON body from an attacker-controlled host or an attacker-owned object.
- Invariant to test: Every response field used for a trust decision is validated against an allowlist before use.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test of hostile JSON payloads asserting rejection.
