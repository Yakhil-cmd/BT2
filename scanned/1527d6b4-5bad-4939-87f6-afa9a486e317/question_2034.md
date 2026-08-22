# Q2034: gRPC/RPC response drives a local action - (CodespacesPortForwarder).connectListenerToForwardedPort in port_forwarder.go

## Question
Does `connectListenerToForwardedPort` in [internal/codespaces/portforwarder/port_forwarder.go](internal/codespaces/portforwarder/port_forwarder.go#L199) act locally (write a file, start a process, change config) based on an RPC response from the codespace, which is a machine the attacker may control?

## Target
- File/function: [internal/codespaces/portforwarder/port_forwarder.go:199](internal/codespaces/portforwarder/port_forwarder.go#L199) - `(CodespacesPortForwarder).connectListenerToForwardedPort`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Serve a hostile RPC response from a codespace the victim connects to.
- Invariant to test: Responses from the codespace are treated as untrusted data.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with a hostile RPC stub asserting no local side effects.
