# Q1861: GraphQL query assembled from remote strings - (LiveClient).getAttestations in client.go

## Question
Can an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims reach the query/variable construction in `getAttestations` in [pkg/cmd/attestation/api/client.go](pkg/cmd/attestation/api/client.go#L142) as raw query text rather than as a typed variable?

## Target
- File/function: [pkg/cmd/attestation/api/client.go:142](pkg/cmd/attestation/api/client.go#L142) - `(LiveClient).getAttestations`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Publish an object whose name is interpolated into the query body.
- Invariant to test: All user/remote values are passed as GraphQL variables.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the sent query body is constant and values travel in variables.
