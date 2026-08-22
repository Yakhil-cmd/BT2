# Q4038: subject/predicate mismatch accepted - DigestAlgForRef in fetch.go

## Question
Can an attestation whose subject name or predicate type does not match the artifact still satisfy `DigestAlgForRef` in [pkg/cmd/release/shared/fetch.go](pkg/cmd/release/shared/fetch.go#L182)?

## Target
- File/function: [pkg/cmd/release/shared/fetch.go:182](pkg/cmd/release/shared/fetch.go#L182) - `DigestAlgForRef`
- Entrypoint: gh release
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a bundle whose statement subject points at a different artifact and attach it to the attacker's binary.
- Invariant to test: Subject digest and predicate type must both be matched before success.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Unit test with a mismatched subject asserting verification fails.
