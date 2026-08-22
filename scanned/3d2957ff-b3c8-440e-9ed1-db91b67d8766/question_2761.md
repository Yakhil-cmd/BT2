# Q2761: editor/jupyter URL opened from response - New in api.go

## Question
Does `New` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L72) open a URL or launch an editor with parameters supplied by the codespace/API response?

## Target
- File/function: [internal/codespaces/api/api.go:72](internal/codespaces/api/api.go#L72) - `New`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Return a URL with a non-http scheme or attacker host.
- Invariant to test: Launched URLs are scheme- and host-validated.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table test of hostile URLs asserting no launch.
