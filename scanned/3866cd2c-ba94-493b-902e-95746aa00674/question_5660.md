# Q5660: logs rendered raw - (codespace).displayName in common.go

## Question
Does `displayName` in [pkg/cmd/codespace/common.go](pkg/cmd/codespace/common.go#L194) stream codespace-side logs to the terminal unsanitized?

## Target
- File/function: [pkg/cmd/codespace/common.go:194](pkg/cmd/codespace/common.go#L194) - `(codespace).displayName`
- Entrypoint: gh codespace common
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Emit control sequences from inside the codespace.
- Invariant to test: Streamed remote output is sanitized.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile log stream.
