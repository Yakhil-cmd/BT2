# Q0557: issue/PR body reaches the terminal raw - printRawPrPreview in view.go

## Question
Does `printRawPrPreview` in [pkg/cmd/pr/view/view.go](pkg/cmd/pr/view/view.go#L141) print a body/title/comment authored by any unprivileged GitHub user without stripping control sequences?

## Target
- File/function: [pkg/cmd/pr/view/view.go:141](pkg/cmd/pr/view/view.go#L141) - `printRawPrPreview`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Open an issue/PR/comment on the victim's repo containing escape payloads; the maintainer runs gh pr view.
- Invariant to test: Every field authored by a third party is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a fixture with CSI/OSC/DCS payloads.
