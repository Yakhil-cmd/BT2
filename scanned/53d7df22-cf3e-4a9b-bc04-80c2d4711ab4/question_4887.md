# Q4887: editor/jupyter URL opened from response - (CodespacesPortForwarder).ForwardPort in port_forwarder.go

## Question
Does `ForwardPort` in [internal/codespaces/portforwarder/port_forwarder.go](internal/codespaces/portforwarder/port_forwarder.go#L104) open a URL or launch an editor with parameters supplied by the codespace/API response?

## Target
- File/function: [internal/codespaces/portforwarder/port_forwarder.go:104](internal/codespaces/portforwarder/port_forwarder.go#L104) - `(CodespacesPortForwarder).ForwardPort`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Return a URL with a non-http scheme or attacker host.
- Invariant to test: Launched URLs are scheme- and host-validated.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table test of hostile URLs asserting no launch.
