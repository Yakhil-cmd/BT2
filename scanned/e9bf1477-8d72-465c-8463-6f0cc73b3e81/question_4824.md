# Q4824: forged gh status/verdict line - Test in iostreams.go

## Question
Can attacker-controlled text rendered by `Test` in [pkg/iostreams/iostreams.go](pkg/iostreams/iostreams.go#L585) reproduce gh's own success/verification markers (checkmarks, colors) so a user reads a failed operation as passed?

## Target
- File/function: [pkg/iostreams/iostreams.go:585](pkg/iostreams/iostreams.go#L585) - `Test`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Embed the marker glyphs and colors in a title/description the victim views.
- Invariant to test: gh's own status glyphs are emitted only by gh and remote text cannot start a line with them.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test asserting remote text is indented/escaped away from status columns.
