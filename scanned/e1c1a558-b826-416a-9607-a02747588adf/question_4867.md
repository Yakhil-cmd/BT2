# Q4867: path/fragment injection into the opened URL - runBrowse in browse.go

## Question
Can an issue/PR title, body, comment, check output, or release note the attacker authored inject `?`, `#`, or additional path segments into the URL assembled in `runBrowse` in [pkg/cmd/browse/browse.go](pkg/cmd/browse/browse.go#L187), redirecting the victim's browser to attacker content on a trusted host?

## Target
- File/function: [pkg/cmd/browse/browse.go:187](pkg/cmd/browse/browse.go#L187) - `runBrowse`
- Entrypoint: gh browse browse
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Use a branch/file name containing `..` or `?` so the resulting page is attacker-chosen.
- Invariant to test: Every user/remote segment is escaped before assembly.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Table test comparing assembled URLs against escaped expectations.
