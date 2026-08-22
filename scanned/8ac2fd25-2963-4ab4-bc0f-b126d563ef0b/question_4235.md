# Q4235: editor/jupyter URL opened from response - (codespace).running in common.go

## Question
Does `running` in [pkg/cmd/codespace/common.go](pkg/cmd/codespace/common.go#L231) open a URL or launch an editor with parameters supplied by the codespace/API response?

## Target
- File/function: [pkg/cmd/codespace/common.go:231](pkg/cmd/codespace/common.go#L231) - `(codespace).running`
- Entrypoint: gh codespace common
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Return a URL with a non-http scheme or attacker host.
- Invariant to test: Launched URLs are scheme- and host-validated.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table test of hostile URLs asserting no launch.
