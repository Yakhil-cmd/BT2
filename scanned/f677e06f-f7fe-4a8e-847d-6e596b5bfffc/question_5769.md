# Q5769: repo override parsing accepts URLs - HttpClientFunc in default.go

## Question
Can the `-R`/base-repo parsing behind `HttpClientFunc` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L188) accept a full URL or host-qualified string that redirects the whole command to a host of the attacker's choosing?

## Target
- File/function: [pkg/cmd/factory/default.go:188](pkg/cmd/factory/default.go#L188) - `HttpClientFunc`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Get the victim to copy a documented command line containing attacker coordinates.
- Invariant to test: Override parsing accepts OWNER/REPO and validated hosts only.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test of override strings asserting host resolution.
