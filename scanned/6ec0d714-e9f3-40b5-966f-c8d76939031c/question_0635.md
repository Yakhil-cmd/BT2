# Q0635: pagination Link header points off-host - (API).EditCodespace in api.go

## Question
Does `EditCodespace` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L1162) follow the `Link: rel=next` URL from the response without re-validating its host against the original request host?

## Target
- File/function: [internal/codespaces/api/api.go:1162](internal/codespaces/api/api.go#L1162) - `(API).EditCodespace`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Return a Link header pointing at the attacker's collector on the first page.
- Invariant to test: Pagination targets must match the origin host and scheme.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: httpmock test returning a cross-host Link and asserting no authenticated follow-up request.
