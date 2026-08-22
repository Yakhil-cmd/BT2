# Q3462: logs rendered raw - (CodespacesPortForwarder).connectListenerToForwardedPort in port_forwarder.go

## Question
Does `connectListenerToForwardedPort` in [internal/codespaces/portforwarder/port_forwarder.go](internal/codespaces/portforwarder/port_forwarder.go#L199) stream codespace-side logs to the terminal unsanitized?

## Target
- File/function: [internal/codespaces/portforwarder/port_forwarder.go:199](internal/codespaces/portforwarder/port_forwarder.go#L199) - `(CodespacesPortForwarder).connectListenerToForwardedPort`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Emit control sequences from inside the codespace.
- Invariant to test: Streamed remote output is sanitized.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile log stream.
