# Q3705: failure path continues execution - (Client).Command in client.go

## Question
If the subprocess launched by `Command` in [git/client.go](git/client.go#L77) fails or returns attacker-shaped stderr, does the caller continue on a fallback path that skips a security check?

## Target
- File/function: [git/client.go:77](git/client.go#L77) - `(Client).Command`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Make the child fail deterministically (e.g. force git to error) so gh falls back to a less-validated code path.
- Invariant to test: A failed subprocess must abort the operation, never downgrade to an unchecked fallback.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Stub the runner to return an error and assert the caller aborts rather than proceeding.
