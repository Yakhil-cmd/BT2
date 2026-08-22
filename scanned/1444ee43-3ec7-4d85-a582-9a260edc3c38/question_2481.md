# Q2481: host shown differs from host used - resolveHosts in install.go

## Question
Does the confirmation in `resolveHosts` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L913) display a host/repo string that is derived differently from the value actually used afterwards?

## Target
- File/function: [pkg/cmd/skills/install/install.go:913](pkg/cmd/skills/install/install.go#L913) - `resolveHosts`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish coordinates where display and action diverge (lookalike host, renamed repo).
- Invariant to test: Displayed and acted-on identifiers come from the same variable.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting the prompt string and the executed target are the same value.
