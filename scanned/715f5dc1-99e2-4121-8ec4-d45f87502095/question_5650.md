# Q5650: logs rendered raw - newPortsForwardCmd in ports.go

## Question
Does `newPortsForwardCmd` in [pkg/cmd/codespace/ports.go](pkg/cmd/codespace/ports.go#L301) stream codespace-side logs to the terminal unsanitized?

## Target
- File/function: [pkg/cmd/codespace/ports.go:301](pkg/cmd/codespace/ports.go#L301) - `newPortsForwardCmd`
- Entrypoint: gh codespace ports
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Emit control sequences from inside the codespace.
- Invariant to test: Streamed remote output is sanitized.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile log stream.
