# Q5795: empty result treated as success - (Client).ShowRefs in client.go

## Question
If the attestation list, bundle set, or policy result reaching `ShowRefs` in [git/client.go](git/client.go#L243) is empty or nil, does the code report success instead of failure?

## Target
- File/function: [git/client.go:243](git/client.go#L243) - `(Client).ShowRefs`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Serve an empty attestations array from the API host for the attacker's artifact.
- Invariant to test: Zero verified attestations always yields a hard failure.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with an empty response asserting a non-zero exit and an error.
