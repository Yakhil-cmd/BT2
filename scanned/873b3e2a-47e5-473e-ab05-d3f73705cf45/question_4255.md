# Q4255: subject/predicate mismatch accepted - downloadCopilot in copilot.go

## Question
Can an attestation whose subject name or predicate type does not match the artifact still satisfy `downloadCopilot` in [pkg/cmd/copilot/copilot.go](pkg/cmd/copilot/copilot.go#L239)?

## Target
- File/function: [pkg/cmd/copilot/copilot.go:239](pkg/cmd/copilot/copilot.go#L239) - `downloadCopilot`
- Entrypoint: gh copilot copilot
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish a bundle whose statement subject points at a different artifact and attach it to the attacker's binary.
- Invariant to test: Subject digest and predicate type must both be matched before success.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Unit test with a mismatched subject asserting verification fails.
