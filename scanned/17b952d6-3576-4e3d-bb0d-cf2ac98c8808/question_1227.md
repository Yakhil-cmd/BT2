# Q1227: host shown differs from host used - editRun in edit.go

## Question
Does the confirmation in `editRun` in [pkg/cmd/gist/edit/edit.go](pkg/cmd/gist/edit/edit.go#L118) display a host/repo string that is derived differently from the value actually used afterwards?

## Target
- File/function: [pkg/cmd/gist/edit/edit.go:118](pkg/cmd/gist/edit/edit.go#L118) - `editRun`
- Entrypoint: gh gist edit
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish coordinates where display and action diverge (lookalike host, renamed repo).
- Invariant to test: Displayed and acted-on identifiers come from the same variable.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting the prompt string and the executed target are the same value.
