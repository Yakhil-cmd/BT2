# Q5429: pagination Link header points off-host - (LiveClient).getAttestations in client.go

## Question
Does `getAttestations` in [pkg/cmd/attestation/api/client.go](pkg/cmd/attestation/api/client.go#L142) follow the `Link: rel=next` URL from the response without re-validating its host against the original request host?

## Target
- File/function: [pkg/cmd/attestation/api/client.go:142](pkg/cmd/attestation/api/client.go#L142) - `(LiveClient).getAttestations`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Return a Link header pointing at the attacker's collector on the first page.
- Invariant to test: Pagination targets must match the origin host and scheme.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: httpmock test returning a cross-host Link and asserting no authenticated follow-up request.
