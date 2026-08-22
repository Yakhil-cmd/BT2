# Q5585: failure path continues execution - Shell in ssh.go

## Question
If the subprocess launched by `Shell` in [internal/codespaces/ssh.go](internal/codespaces/ssh.go#L21) fails or returns attacker-shaped stderr, does the caller continue on a fallback path that skips a security check?

## Target
- File/function: [internal/codespaces/ssh.go:21](internal/codespaces/ssh.go#L21) - `Shell`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Make the child fail deterministically (e.g. force git to error) so gh falls back to a less-validated code path.
- Invariant to test: A failed subprocess must abort the operation, never downgrade to an unchecked fallback.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Stub the runner to return an error and assert the caller aborts rather than proceeding.
