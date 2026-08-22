# Q2024: editor/jupyter URL opened from response - waitUntilCodespaceConnectionReady in codespaces.go

## Question
Does `waitUntilCodespaceConnectionReady` in [internal/codespaces/codespaces.go](internal/codespaces/codespaces.go#L78) open a URL or launch an editor with parameters supplied by the codespace/API response?

## Target
- File/function: [internal/codespaces/codespaces.go:78](internal/codespaces/codespaces.go#L78) - `waitUntilCodespaceConnectionReady`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Return a URL with a non-http scheme or attacker host.
- Invariant to test: Launched URLs are scheme- and host-validated.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table test of hostile URLs asserting no launch.
