# Q1296: truncated identity in a security-relevant list - printTable in output.go

## Question
Does the table/list built by `printTable` in [pkg/cmd/pr/checks/output.go](pkg/cmd/pr/checks/output.go#L94) elide the owner or host portion of an identifier that the user relies on to distinguish a legitimate object from an attacker's lookalike?

## Target
- File/function: [pkg/cmd/pr/checks/output.go:94](pkg/cmd/pr/checks/output.go#L94) - `printTable`
- Entrypoint: gh pr checks
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a lookalike object with a long prefix.
- Invariant to test: Identifiers are shown in full for security-relevant listings.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting full identifiers for long names.
