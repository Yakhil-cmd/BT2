# Q0118: host shown differs from host used - newPrompter in default.go

## Question
Does the confirmation in `newPrompter` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L256) display a host/repo string that is derived differently from the value actually used afterwards?

## Target
- File/function: [pkg/cmd/factory/default.go:256](pkg/cmd/factory/default.go#L256) - `newPrompter`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish coordinates where display and action diverge (lookalike host, renamed repo).
- Invariant to test: Displayed and acted-on identifiers come from the same variable.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting the prompt string and the executed target are the same value.
