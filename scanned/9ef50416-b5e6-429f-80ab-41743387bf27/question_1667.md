# Q1667: failure path continues execution - codesignBinary in manager.go

## Question
If the subprocess launched by `codesignBinary` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L854) fails or returns attacker-shaped stderr, does the caller continue on a fallback path that skips a security check?

## Target
- File/function: [pkg/cmd/extension/manager.go:854](pkg/cmd/extension/manager.go#L854) - `codesignBinary`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Make the child fail deterministically (e.g. force git to error) so gh falls back to a less-validated code path.
- Invariant to test: A failed subprocess must abort the operation, never downgrade to an unchecked fallback.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Stub the runner to return an error and assert the caller aborts rather than proceeding.
