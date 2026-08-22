# Q4232: logs rendered raw - (App).RunWithProgress in common.go

## Question
Does `RunWithProgress` in [pkg/cmd/codespace/common.go](pkg/cmd/codespace/common.go#L63) stream codespace-side logs to the terminal unsanitized?

## Target
- File/function: [pkg/cmd/codespace/common.go:63](pkg/cmd/codespace/common.go#L63) - `(App).RunWithProgress`
- Entrypoint: gh codespace common
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Emit control sequences from inside the codespace.
- Invariant to test: Streamed remote output is sanitized.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile log stream.
