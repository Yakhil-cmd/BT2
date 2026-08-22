# Q4133: forged gh status/verdict line - prProjectList in view.go

## Question
Can attacker-controlled text rendered by `prProjectList` in [pkg/cmd/pr/view/view.go](pkg/cmd/pr/view/view.go#L441) reproduce gh's own success/verification markers (checkmarks, colors) so a user reads a failed operation as passed?

## Target
- File/function: [pkg/cmd/pr/view/view.go:441](pkg/cmd/pr/view/view.go#L441) - `prProjectList`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Embed the marker glyphs and colors in a title/description the victim views.
- Invariant to test: gh's own status glyphs are emitted only by gh and remote text cannot start a line with them.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test asserting remote text is indented/escaped away from status columns.
