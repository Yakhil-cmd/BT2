# Q5579: forged gh status/verdict line - NewCmdBrowse in browse.go

## Question
Can attacker-controlled text rendered by `NewCmdBrowse` in [pkg/cmd/browse/browse.go](pkg/cmd/browse/browse.go#L52) reproduce gh's own success/verification markers (checkmarks, colors) so a user reads a failed operation as passed?

## Target
- File/function: [pkg/cmd/browse/browse.go:52](pkg/cmd/browse/browse.go#L52) - `NewCmdBrowse`
- Entrypoint: gh browse browse
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Embed the marker glyphs and colors in a title/description the victim views.
- Invariant to test: gh's own status glyphs are emitted only by gh and remote text cannot start a line with them.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test asserting remote text is indented/escaped away from status columns.
