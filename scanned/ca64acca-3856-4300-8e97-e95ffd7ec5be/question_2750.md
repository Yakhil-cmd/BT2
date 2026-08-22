# Q2750: gRPC/RPC response drives a local action - (CodespacesPortForwarder).UpdatePortVisibility in port_forwarder.go

## Question
Does `UpdatePortVisibility` in [internal/codespaces/portforwarder/port_forwarder.go](internal/codespaces/portforwarder/port_forwarder.go#L272) act locally (write a file, start a process, change config) based on an RPC response from the codespace, which is a machine the attacker may control?

## Target
- File/function: [internal/codespaces/portforwarder/port_forwarder.go:272](internal/codespaces/portforwarder/port_forwarder.go#L272) - `(CodespacesPortForwarder).UpdatePortVisibility`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Serve a hostile RPC response from a codespace the victim connects to.
- Invariant to test: Responses from the codespace are treated as untrusted data.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with a hostile RPC stub asserting no local side effects.
