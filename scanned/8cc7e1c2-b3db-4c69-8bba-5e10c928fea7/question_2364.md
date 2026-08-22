# Q2364: pager/child renderer receives raw bytes - (Manager).installBin in manager.go

## Question
Does `installBin` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L282) hand unsanitized remote text to a pager or external renderer where escape handling differs from gh's own?

## Target
- File/function: [pkg/cmd/extension/manager.go:282](pkg/cmd/extension/manager.go#L282) - `(Manager).installBin`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish content whose escapes are inert in gh but active in the pager.
- Invariant to test: Sanitization is applied before the bytes leave gh, regardless of the sink.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting the bytes written to a stub pager are already sanitized.
