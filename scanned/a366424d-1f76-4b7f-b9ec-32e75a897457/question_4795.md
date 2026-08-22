# Q4795: prompt/output spoofing with CR and newline - NewCmdEdit in edit.go

## Question
Can carriage returns or newlines in an asset, artifact, gist, or archive-member name and its bytes rendered by `NewCmdEdit` in [pkg/cmd/gist/edit/edit.go](pkg/cmd/gist/edit/edit.go#L45) overwrite earlier lines and forge gh's own trusted output or a credential prompt?

## Target
- File/function: [pkg/cmd/gist/edit/edit.go:45](pkg/cmd/gist/edit/edit.go#L45) - `NewCmdEdit`
- Entrypoint: gh gist edit
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Craft a name/title that redraws the line as `? Paste your GitHub token:`.
- Invariant to test: Remote text is escaped so it cannot emit CR or reposition the cursor.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting `\r` and cursor-movement sequences never appear in rendered output.
