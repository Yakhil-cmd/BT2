# Q3525: pagination Link header points off-host - newCAPITransport in client.go

## Question
Does `newCAPITransport` in [pkg/cmd/agent-task/capi/client.go](pkg/cmd/agent-task/capi/client.go#L52) follow the `Link: rel=next` URL from the response without re-validating its host against the original request host?

## Target
- File/function: [pkg/cmd/agent-task/capi/client.go:52](pkg/cmd/agent-task/capi/client.go#L52) - `newCAPITransport`
- Entrypoint: gh agent task
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Return a Link header pointing at the attacker's collector on the first page.
- Invariant to test: Pagination targets must match the origin host and scheme.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: httpmock test returning a cross-host Link and asserting no authenticated follow-up request.
