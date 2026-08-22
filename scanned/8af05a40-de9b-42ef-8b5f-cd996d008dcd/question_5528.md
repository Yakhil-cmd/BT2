# Q5528: issue/PR body reaches the terminal raw - (IOStreams).startTextualProgressIndicator in iostreams.go

## Question
Does `startTextualProgressIndicator` in [pkg/iostreams/iostreams.go](pkg/iostreams/iostreams.go#L342) print a body/title/comment authored by any unprivileged GitHub user without stripping control sequences?

## Target
- File/function: [pkg/iostreams/iostreams.go:342](pkg/iostreams/iostreams.go#L342) - `(IOStreams).startTextualProgressIndicator`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Open an issue/PR/comment on the victim's repo containing escape payloads; the maintainer runs gh pr view.
- Invariant to test: Every field authored by a third party is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a fixture with CSI/OSC/DCS payloads.
