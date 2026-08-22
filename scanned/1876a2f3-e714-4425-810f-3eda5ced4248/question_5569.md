# Q5569: issue/PR body reaches the terminal raw - PrCheckStatusSummaryWithColor in display.go

## Question
Does `PrCheckStatusSummaryWithColor` in [pkg/cmd/pr/shared/display.go](pkg/cmd/pr/shared/display.go#L85) print a body/title/comment authored by any unprivileged GitHub user without stripping control sequences?

## Target
- File/function: [pkg/cmd/pr/shared/display.go:85](pkg/cmd/pr/shared/display.go#L85) - `PrCheckStatusSummaryWithColor`
- Entrypoint: gh pr
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Open an issue/PR/comment on the victim's repo containing escape payloads; the maintainer runs gh pr.
- Invariant to test: Every field authored by a third party is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a fixture with CSI/OSC/DCS payloads.
