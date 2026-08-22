# Q3465: logs rendered raw - AccessControlEntriesToVisibility in port_forwarder.go

## Question
Does `AccessControlEntriesToVisibility` in [internal/codespaces/portforwarder/port_forwarder.go](internal/codespaces/portforwarder/port_forwarder.go#L362) stream codespace-side logs to the terminal unsanitized?

## Target
- File/function: [internal/codespaces/portforwarder/port_forwarder.go:362](internal/codespaces/portforwarder/port_forwarder.go#L362) - `AccessControlEntriesToVisibility`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Emit control sequences from inside the codespace.
- Invariant to test: Streamed remote output is sanitized.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile log stream.
