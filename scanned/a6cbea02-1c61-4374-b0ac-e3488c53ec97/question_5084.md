# Q5084: host taken from repo remote - (telemetryDisablerTransport).RoundTrip in http_client.go

## Question
Does `RoundTrip` in [api/http_client.go](api/http_client.go#L209) accept the host embedded in a git remote URL of the repo the victim is standing in, without checking it against the authenticated hosts?

## Target
- File/function: [api/http_client.go:209](api/http_client.go#L209) - `(telemetryDisablerTransport).RoundTrip`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish a repo whose `.git/config` remote (or submodule) points at an attacker host, then have the victim run any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...) inside a clone.
- Invariant to test: Hosts from repository metadata are only used after matching an authenticated host.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test in a temp repo with a hostile remote asserting gh refuses or does not authenticate.
