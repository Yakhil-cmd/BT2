# Q2806: editor/jupyter URL opened from response - (codespace).displayName in common.go

## Question
Does `displayName` in [pkg/cmd/codespace/common.go](pkg/cmd/codespace/common.go#L194) open a URL or launch an editor with parameters supplied by the codespace/API response?

## Target
- File/function: [pkg/cmd/codespace/common.go:194](pkg/cmd/codespace/common.go#L194) - `(codespace).displayName`
- Entrypoint: gh codespace common
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Return a URL with a non-http scheme or attacker host.
- Invariant to test: Launched URLs are scheme- and host-validated.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table test of hostile URLs asserting no launch.
