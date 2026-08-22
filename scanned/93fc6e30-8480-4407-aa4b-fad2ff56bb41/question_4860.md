# Q4860: forged gh status/verdict line - formatComment in comments.go

## Question
Can attacker-controlled text rendered by `formatComment` in [pkg/cmd/pr/shared/comments.go](pkg/cmd/pr/shared/comments.go#L89) reproduce gh's own success/verification markers (checkmarks, colors) so a user reads a failed operation as passed?

## Target
- File/function: [pkg/cmd/pr/shared/comments.go:89](pkg/cmd/pr/shared/comments.go#L89) - `formatComment`
- Entrypoint: gh pr
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Embed the marker glyphs and colors in a title/description the victim views.
- Invariant to test: gh's own status glyphs are emitted only by gh and remote text cannot start a line with them.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test asserting remote text is indented/escaped away from status columns.
