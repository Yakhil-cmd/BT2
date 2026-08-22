# Q2802: host shown differs from host used - (App).Jupyter in jupyter.go

## Question
Does the confirmation in `Jupyter` in [pkg/cmd/codespace/jupyter.go](pkg/cmd/codespace/jupyter.go#L32) display a host/repo string that is derived differently from the value actually used afterwards?

## Target
- File/function: [pkg/cmd/codespace/jupyter.go:32](pkg/cmd/codespace/jupyter.go#L32) - `(App).Jupyter`
- Entrypoint: gh codespace jupyter
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish coordinates where display and action diverge (lookalike host, renamed repo).
- Invariant to test: Displayed and acted-on identifiers come from the same variable.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting the prompt string and the executed target are the same value.
