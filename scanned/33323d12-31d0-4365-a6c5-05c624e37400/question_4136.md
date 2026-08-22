# Q4136: truncated identity in a security-relevant list - printRawIssuePreview in view.go

## Question
Does the table/list built by `printRawIssuePreview` in [pkg/cmd/issue/view/view.go](pkg/cmd/issue/view/view.go#L197) elide the owner or host portion of an identifier that the user relies on to distinguish a legitimate object from an attacker's lookalike?

## Target
- File/function: [pkg/cmd/issue/view/view.go:197](pkg/cmd/issue/view/view.go#L197) - `printRawIssuePreview`
- Entrypoint: gh issue view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a lookalike object with a long prefix.
- Invariant to test: Identifiers are shown in full for security-relevant listings.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting full identifiers for long names.
