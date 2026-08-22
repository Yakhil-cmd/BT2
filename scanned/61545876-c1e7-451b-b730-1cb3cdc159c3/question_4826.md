# Q4826: issue/PR body reaches the terminal raw - CopyGuardedContent in content.go

## Question
Does `CopyGuardedContent` in [pkg/iostreams/content.go](pkg/iostreams/content.go#L63) print a body/title/comment authored by any unprivileged GitHub user without stripping control sequences?

## Target
- File/function: [pkg/iostreams/content.go:63](pkg/iostreams/content.go#L63) - `CopyGuardedContent`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Open an issue/PR/comment on the victim's repo containing escape payloads; the maintainer runs gh pr view.
- Invariant to test: Every field authored by a third party is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a fixture with CSI/OSC/DCS payloads.
