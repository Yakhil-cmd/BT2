# Q4771: pagination Link header points off-host - (apiLogFetcher).GetLog in logs.go

## Question
Does `GetLog` in [pkg/cmd/run/view/logs.go](pkg/cmd/run/view/logs.go#L42) follow the `Link: rel=next` URL from the response without re-validating its host against the original request host?

## Target
- File/function: [pkg/cmd/run/view/logs.go:42](pkg/cmd/run/view/logs.go#L42) - `(apiLogFetcher).GetLog`
- Entrypoint: gh run view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Return a Link header pointing at the attacker's collector on the first page.
- Invariant to test: Pagination targets must match the origin host and scheme.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: httpmock test returning a cross-host Link and asserting no authenticated follow-up request.
