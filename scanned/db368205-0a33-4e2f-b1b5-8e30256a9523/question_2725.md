# Q2725: issue/PR body reaches the terminal raw - NewCmdBrowse in browse.go

## Question
Does `NewCmdBrowse` in [pkg/cmd/browse/browse.go](pkg/cmd/browse/browse.go#L52) print a body/title/comment authored by any unprivileged GitHub user without stripping control sequences?

## Target
- File/function: [pkg/cmd/browse/browse.go:52](pkg/cmd/browse/browse.go#L52) - `NewCmdBrowse`
- Entrypoint: gh browse browse
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Open an issue/PR/comment on the victim's repo containing escape payloads; the maintainer runs gh browse browse.
- Invariant to test: Every field authored by a third party is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a fixture with CSI/OSC/DCS payloads.
