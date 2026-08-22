# Q2027: editor/jupyter URL opened from response - (CodespaceConnection).Connect in connection.go

## Question
Does `Connect` in [internal/codespaces/connection/connection.go](internal/codespaces/connection/connection.go#L89) open a URL or launch an editor with parameters supplied by the codespace/API response?

## Target
- File/function: [internal/codespaces/connection/connection.go:89](internal/codespaces/connection/connection.go#L89) - `(CodespaceConnection).Connect`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Return a URL with a non-http scheme or attacker host.
- Invariant to test: Launched URLs are scheme- and host-validated.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table test of hostile URLs asserting no launch.
