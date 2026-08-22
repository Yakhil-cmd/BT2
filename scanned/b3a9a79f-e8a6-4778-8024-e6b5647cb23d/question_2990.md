# Q2990: repo override parsing accepts URLs - startPage in pagination.go

## Question
Can the `-R`/base-repo parsing behind `startPage` in [pkg/cmd/api/pagination.go](pkg/cmd/api/pagination.go#L210) accept a full URL or host-qualified string that redirects the whole command to a host of the attacker's choosing?

## Target
- File/function: [pkg/cmd/api/pagination.go:210](pkg/cmd/api/pagination.go#L210) - `startPage`
- Entrypoint: gh api pagination
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Get the victim to copy a documented command line containing attacker coordinates.
- Invariant to test: Override parsing accepts OWNER/REPO and validated hosts only.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test of override strings asserting host resolution.
