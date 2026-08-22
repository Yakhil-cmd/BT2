# Q4557: pager/child renderer receives raw bytes - printError in cmd.go

## Question
Does `printError` in [internal/ghcmd/cmd.go](internal/ghcmd/cmd.go#L282) hand unsanitized remote text to a pager or external renderer where escape handling differs from gh's own?

## Target
- File/function: [internal/ghcmd/cmd.go:282](internal/ghcmd/cmd.go#L282) - `printError`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish content whose escapes are inert in gh but active in the pager.
- Invariant to test: Sanitization is applied before the bytes leave gh, regardless of the sink.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting the bytes written to a stub pager are already sanitized.
