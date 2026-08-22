# Q0352: pager/child renderer receives raw bytes - checkUpstreamProvenance in install.go

## Question
Does `checkUpstreamProvenance` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L1299) hand unsanitized remote text to a pager or external renderer where escape handling differs from gh's own?

## Target
- File/function: [pkg/cmd/skills/install/install.go:1299](pkg/cmd/skills/install/install.go#L1299) - `checkUpstreamProvenance`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish content whose escapes are inert in gh but active in the pager.
- Invariant to test: Sanitization is applied before the bytes leave gh, regardless of the sink.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting the bytes written to a stub pager are already sanitized.
