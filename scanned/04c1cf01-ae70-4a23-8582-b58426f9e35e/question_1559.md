# Q1559: response used to overwrite local config - (paginatedArrayReader).Read in pagination.go

## Question
Can data returned through `Read` in [pkg/cmd/api/pagination.go](pkg/cmd/api/pagination.go#L123) be written into gh's own configuration (default host, aliases, editor, browser) without validation?

## Target
- File/function: [pkg/cmd/api/pagination.go:123](pkg/cmd/api/pagination.go#L123) - `(paginatedArrayReader).Read`
- Entrypoint: gh api pagination
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Return a crafted object whose field is persisted locally.
- Invariant to test: Persisted config values come from user input, not from responses.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting no config write results from a hostile response.
