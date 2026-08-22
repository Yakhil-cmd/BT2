# Q5565: forged gh status/verdict line - issueProjectList in view.go

## Question
Can attacker-controlled text rendered by `issueProjectList` in [pkg/cmd/issue/view/view.go](pkg/cmd/issue/view/view.go#L412) reproduce gh's own success/verification markers (checkmarks, colors) so a user reads a failed operation as passed?

## Target
- File/function: [pkg/cmd/issue/view/view.go:412](pkg/cmd/issue/view/view.go#L412) - `issueProjectList`
- Entrypoint: gh issue view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Embed the marker glyphs and colors in a title/description the victim views.
- Invariant to test: gh's own status glyphs are emitted only by gh and remote text cannot start a line with them.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test asserting remote text is indented/escaped away from status columns.
