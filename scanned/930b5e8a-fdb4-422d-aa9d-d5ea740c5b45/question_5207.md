# Q5207: pager/child renderer receives raw bytes - printLinkedBranches in develop.go

## Question
Does `printLinkedBranches` in [pkg/cmd/issue/develop/develop.go](pkg/cmd/issue/develop/develop.go#L342) hand unsanitized remote text to a pager or external renderer where escape handling differs from gh's own?

## Target
- File/function: [pkg/cmd/issue/develop/develop.go:342](pkg/cmd/issue/develop/develop.go#L342) - `printLinkedBranches`
- Entrypoint: gh issue develop
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish content whose escapes are inert in gh but active in the pager.
- Invariant to test: Sanitization is applied before the bytes leave gh, regardless of the sink.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting the bytes written to a stub pager are already sanitized.
