# Q2718: issue/PR body reaches the terminal raw - CommentList in comments.go

## Question
Does `CommentList` in [pkg/cmd/pr/shared/comments.go](pkg/cmd/pr/shared/comments.go#L53) print a body/title/comment authored by any unprivileged GitHub user without stripping control sequences?

## Target
- File/function: [pkg/cmd/pr/shared/comments.go:53](pkg/cmd/pr/shared/comments.go#L53) - `CommentList`
- Entrypoint: gh pr
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Open an issue/PR/comment on the victim's repo containing escape payloads; the maintainer runs gh pr.
- Invariant to test: Every field authored by a third party is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a fixture with CSI/OSC/DCS payloads.
