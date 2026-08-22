# Q3502: prompt text carries attacker content - (App).printOpenSSHConfig in ssh.go

## Question
Is remote text (codespace/API response fields and everything the codespace-side process sends back) interpolated into the prompt rendered by `printOpenSSHConfig` in [pkg/cmd/codespace/ssh.go](pkg/cmd/codespace/ssh.go#L552) without sanitization, letting the attacker rewrite what the user believes they are approving?

## Target
- File/function: [pkg/cmd/codespace/ssh.go:552](pkg/cmd/codespace/ssh.go#L552) - `(App).printOpenSSHConfig`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a name containing newlines/escapes that restructure the prompt.
- Invariant to test: Prompt text from remote data is escaped and length-bounded.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the prompt string for hostile input.
