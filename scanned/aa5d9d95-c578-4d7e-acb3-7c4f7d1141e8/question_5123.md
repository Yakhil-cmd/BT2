# Q5123: response used to overwrite local config - fillPlaceholders in api.go

## Question
Can data returned through `fillPlaceholders` in [pkg/cmd/api/api.go](pkg/cmd/api/api.go#L574) be written into gh's own configuration (default host, aliases, editor, browser) without validation?

## Target
- File/function: [pkg/cmd/api/api.go:574](pkg/cmd/api/api.go#L574) - `fillPlaceholders`
- Entrypoint: gh api
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Return a crafted object whose field is persisted locally.
- Invariant to test: Persisted config values come from user input, not from responses.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting no config write results from a hostile response.
