# Q2009: issue/PR body reaches the terminal raw - printSummary in output.go

## Question
Does `printSummary` in [pkg/cmd/pr/checks/output.go](pkg/cmd/pr/checks/output.go#L69) print a body/title/comment authored by any unprivileged GitHub user without stripping control sequences?

## Target
- File/function: [pkg/cmd/pr/checks/output.go:69](pkg/cmd/pr/checks/output.go#L69) - `printSummary`
- Entrypoint: gh pr checks
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Open an issue/PR/comment on the victim's repo containing escape payloads; the maintainer runs gh pr checks.
- Invariant to test: Every field authored by a third party is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a fixture with CSI/OSC/DCS payloads.
