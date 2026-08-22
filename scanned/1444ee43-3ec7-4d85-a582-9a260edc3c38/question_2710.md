# Q2710: issue/PR body reaches the terminal raw - issueAssigneeList in view.go

## Question
Does `issueAssigneeList` in [pkg/cmd/issue/view/view.go](pkg/cmd/issue/view/view.go#L395) print a body/title/comment authored by any unprivileged GitHub user without stripping control sequences?

## Target
- File/function: [pkg/cmd/issue/view/view.go:395](pkg/cmd/issue/view/view.go#L395) - `issueAssigneeList`
- Entrypoint: gh issue view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Open an issue/PR/comment on the victim's repo containing escape payloads; the maintainer runs gh issue view.
- Invariant to test: Every field authored by a third party is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a fixture with CSI/OSC/DCS payloads.
