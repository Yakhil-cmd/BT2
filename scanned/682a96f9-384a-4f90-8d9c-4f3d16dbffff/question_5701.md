# Q5701: self-update fetches an unverified binary - GetSecretEntity in shared.go

## Question
Does `GetSecretEntity` in [pkg/cmd/secret/shared/shared.go](pkg/cmd/secret/shared/shared.go#L46) decide on or fetch an update using data from a response (version string, URL) without pinning host and verifying integrity?

## Target
- File/function: [pkg/cmd/secret/shared/shared.go:46](pkg/cmd/secret/shared/shared.go#L46) - `GetSecretEntity`
- Entrypoint: gh secret
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Serve a crafted release payload to the update check.
- Invariant to test: Update checks are host-pinned and any downloaded artifact is verified.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with a hostile release payload asserting no unverified fetch.
