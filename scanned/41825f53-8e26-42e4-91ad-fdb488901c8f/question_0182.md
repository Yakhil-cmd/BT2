# Q0182: host shown differs from host used - setDefaultRun in setdefault.go

## Question
Does the confirmation in `setDefaultRun` in [pkg/cmd/repo/setdefault/setdefault.go](pkg/cmd/repo/setdefault/setdefault.go#L126) display a host/repo string that is derived differently from the value actually used afterwards?

## Target
- File/function: [pkg/cmd/repo/setdefault/setdefault.go:126](pkg/cmd/repo/setdefault/setdefault.go#L126) - `setDefaultRun`
- Entrypoint: gh repo setdefault
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish coordinates where display and action diverge (lookalike host, renamed repo).
- Invariant to test: Displayed and acted-on identifiers come from the same variable.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting the prompt string and the executed target are the same value.
