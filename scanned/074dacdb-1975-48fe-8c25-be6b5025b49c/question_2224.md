# Q2224: repo override parsing accepts URLs - NewExternalHTTPClient in http_client.go

## Question
Can the `-R`/base-repo parsing behind `NewExternalHTTPClient` in [api/http_client.go](api/http_client.go#L100) accept a full URL or host-qualified string that redirects the whole command to a host of the attacker's choosing?

## Target
- File/function: [api/http_client.go:100](api/http_client.go#L100) - `NewExternalHTTPClient`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Get the victim to copy a documented command line containing attacker coordinates.
- Invariant to test: Override parsing accepts OWNER/REPO and validated hosts only.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test of override strings asserting host resolution.
