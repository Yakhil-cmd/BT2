# Q0570: issue/PR body reaches the terminal raw - issueLabelList in view.go

## Question
Does `issueLabelList` in [pkg/cmd/issue/view/view.go](pkg/cmd/issue/view/view.go#L446) print a body/title/comment authored by any unprivileged GitHub user without stripping control sequences?

## Target
- File/function: [pkg/cmd/issue/view/view.go:446](pkg/cmd/issue/view/view.go#L446) - `issueLabelList`
- Entrypoint: gh issue view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Open an issue/PR/comment on the victim's repo containing escape payloads; the maintainer runs gh issue view.
- Invariant to test: Every field authored by a third party is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a fixture with CSI/OSC/DCS payloads.
