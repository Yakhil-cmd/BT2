# Q0395: GraphQL query assembled from remote strings - runVerify in verify.go

## Question
Can an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims reach the query/variable construction in `runVerify` in [pkg/cmd/attestation/verify/verify.go](pkg/cmd/attestation/verify/verify.go#L264) as raw query text rather than as a typed variable?

## Target
- File/function: [pkg/cmd/attestation/verify/verify.go:264](pkg/cmd/attestation/verify/verify.go#L264) - `runVerify`
- Entrypoint: gh attestation verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Publish an object whose name is interpolated into the query body.
- Invariant to test: All user/remote values are passed as GraphQL variables.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the sent query body is constant and values travel in variables.
