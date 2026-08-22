# Q4186: logs rendered raw - (invoker).heartbeat in invoker.go

## Question
Does `heartbeat` in [internal/codespaces/rpc/invoker.go](internal/codespaces/rpc/invoker.go#L277) stream codespace-side logs to the terminal unsanitized?

## Target
- File/function: [internal/codespaces/rpc/invoker.go:277](internal/codespaces/rpc/invoker.go#L277) - `(invoker).heartbeat`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Emit control sequences from inside the codespace.
- Invariant to test: Streamed remote output is sanitized.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile log stream.
