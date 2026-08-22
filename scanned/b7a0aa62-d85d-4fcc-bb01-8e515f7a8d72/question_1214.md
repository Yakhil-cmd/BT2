# Q1214: prompt/output spoofing with CR and newline - readFileRun in read_file.go

## Question
Can carriage returns or newlines in an asset, artifact, gist, or archive-member name and its bytes rendered by `readFileRun` in [pkg/cmd/repo/read-file/read_file.go](pkg/cmd/repo/read-file/read_file.go#L128) overwrite earlier lines and forge gh's own trusted output or a credential prompt?

## Target
- File/function: [pkg/cmd/repo/read-file/read_file.go:128](pkg/cmd/repo/read-file/read_file.go#L128) - `readFileRun`
- Entrypoint: gh repo read-file
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Craft a name/title that redraws the line as `? Paste your GitHub token:`.
- Invariant to test: Remote text is escaped so it cannot emit CR or reposition the cursor.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting `\r` and cursor-movement sequences never appear in rendered output.
