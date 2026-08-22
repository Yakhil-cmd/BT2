# Q0982: auto-open without confirmation - NewCmdRoot in root.go

## Question
Does the flow through `NewCmdRoot` in [pkg/cmd/root/root.go](pkg/cmd/root/root.go#L64) open a remote-supplied URL without the user explicitly asking, enabling drive-by navigation from a routine command?

## Target
- File/function: [pkg/cmd/root/root.go:64](pkg/cmd/root/root.go#L64) - `NewCmdRoot`
- Entrypoint: gh root root
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish an object whose listing/view path triggers the open.
- Invariant to test: Browser launches require an explicit user action or flag.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting no opener call on non-interactive/list paths.
