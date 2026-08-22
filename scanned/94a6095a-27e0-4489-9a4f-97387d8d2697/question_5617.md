# Q5617: editor/jupyter URL opened from response - (API).GetRepository in api.go

## Question
Does `GetRepository` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L167) open a URL or launch an editor with parameters supplied by the codespace/API response?

## Target
- File/function: [internal/codespaces/api/api.go:167](internal/codespaces/api/api.go#L167) - `(API).GetRepository`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Return a URL with a non-http scheme or attacker host.
- Invariant to test: Launched URLs are scheme- and host-validated.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table test of hostile URLs asserting no launch.
