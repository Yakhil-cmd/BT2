# Q3259: subject/predicate mismatch accepted - (Options).Clean in options.go

## Question
Can an attestation whose subject name or predicate type does not match the artifact still satisfy `Clean` in [pkg/cmd/attestation/verify/options.go](pkg/cmd/attestation/verify/options.go#L50)?

## Target
- File/function: [pkg/cmd/attestation/verify/options.go:50](pkg/cmd/attestation/verify/options.go#L50) - `(Options).Clean`
- Entrypoint: gh attestation verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Publish a bundle whose statement subject points at a different artifact and attach it to the attacker's binary.
- Invariant to test: Subject digest and predicate type must both be matched before success.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Unit test with a mismatched subject asserting verification fails.
