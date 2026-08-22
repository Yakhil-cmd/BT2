# Q3687: request built from a response field - newBrowser in default.go

## Question
Does `newBrowser` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L251) build a follow-up authenticated request from a URL field of a previous response (download_url, archive_url, next, html_url) without re-validating the host?

## Target
- File/function: [pkg/cmd/factory/default.go:251](pkg/cmd/factory/default.go#L251) - `newBrowser`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Return a hostile URL in that field for the attacker's own object.
- Invariant to test: Follow-up URLs are re-validated against the authenticated host.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: httpmock test with a hostile URL field asserting no authenticated request.
