# Q3506: logs rendered raw - (App).ListPorts in ports.go

## Question
Does `ListPorts` in [pkg/cmd/codespace/ports.go](pkg/cmd/codespace/ports.go#L53) stream codespace-side logs to the terminal unsanitized?

## Target
- File/function: [pkg/cmd/codespace/ports.go:53](pkg/cmd/codespace/ports.go#L53) - `(App).ListPorts`
- Entrypoint: gh codespace ports
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Emit control sequences from inside the codespace.
- Invariant to test: Streamed remote output is sanitized.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile log stream.
