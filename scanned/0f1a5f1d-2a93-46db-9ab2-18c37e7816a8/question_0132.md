# Q0132: request built from a response field - (jsonArrayWriter).ReadFrom in pagination.go

## Question
Does `ReadFrom` in [pkg/cmd/api/pagination.go](pkg/cmd/api/pagination.go#L169) build a follow-up authenticated request from a URL field of a previous response (download_url, archive_url, next, html_url) without re-validating the host?

## Target
- File/function: [pkg/cmd/api/pagination.go:169](pkg/cmd/api/pagination.go#L169) - `(jsonArrayWriter).ReadFrom`
- Entrypoint: gh api pagination
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Return a hostile URL in that field for the attacker's own object.
- Invariant to test: Follow-up URLs are re-validated against the authenticated host.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: httpmock test with a hostile URL field asserting no authenticated request.
