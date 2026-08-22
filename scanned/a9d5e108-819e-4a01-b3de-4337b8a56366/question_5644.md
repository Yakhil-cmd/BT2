# Q5644: editor/jupyter URL opened from response - (App).Copy in ssh.go

## Question
Does `Copy` in [pkg/cmd/codespace/ssh.go](pkg/cmd/codespace/ssh.go#L760) open a URL or launch an editor with parameters supplied by the codespace/API response?

## Target
- File/function: [pkg/cmd/codespace/ssh.go:760](pkg/cmd/codespace/ssh.go#L760) - `(App).Copy`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Return a URL with a non-http scheme or attacker host.
- Invariant to test: Launched URLs are scheme- and host-validated.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table test of hostile URLs asserting no launch.
