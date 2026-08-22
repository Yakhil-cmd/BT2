# Q4425: subject/predicate mismatch accepted - (Client).ShowRefs in client.go

## Question
Can an attestation whose subject name or predicate type does not match the artifact still satisfy `ShowRefs` in [git/client.go](git/client.go#L243)?

## Target
- File/function: [git/client.go:243](git/client.go#L243) - `(Client).ShowRefs`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a bundle whose statement subject points at a different artifact and attach it to the attacker's binary.
- Invariant to test: Subject digest and predicate type must both be matched before success.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Unit test with a mismatched subject asserting verification fails.
