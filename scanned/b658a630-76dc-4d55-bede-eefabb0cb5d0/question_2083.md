# Q2083: prompt text carries attacker content - (App).ForwardPorts in ports.go

## Question
Is remote text (codespace/API response fields and everything the codespace-side process sends back) interpolated into the prompt rendered by `ForwardPorts` in [pkg/cmd/codespace/ports.go](pkg/cmd/codespace/ports.go#L324) without sanitization, letting the attacker rewrite what the user believes they are approving?

## Target
- File/function: [pkg/cmd/codespace/ports.go:324](pkg/cmd/codespace/ports.go#L324) - `(App).ForwardPorts`
- Entrypoint: gh codespace ports
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a name containing newlines/escapes that restructure the prompt.
- Invariant to test: Prompt text from remote data is escaped and length-bounded.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the prompt string for hostile input.
