# Q0578: forged gh status/verdict line - sortComments in comments.go

## Question
Can attacker-controlled text rendered by `sortComments` in [pkg/cmd/pr/shared/comments.go](pkg/cmd/pr/shared/comments.go#L144) reproduce gh's own success/verification markers (checkmarks, colors) so a user reads a failed operation as passed?

## Target
- File/function: [pkg/cmd/pr/shared/comments.go:144](pkg/cmd/pr/shared/comments.go#L144) - `sortComments`
- Entrypoint: gh pr
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Embed the marker glyphs and colors in a title/description the victim views.
- Invariant to test: gh's own status glyphs are emitted only by gh and remote text cannot start a line with them.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test asserting remote text is indented/escaped away from status columns.
