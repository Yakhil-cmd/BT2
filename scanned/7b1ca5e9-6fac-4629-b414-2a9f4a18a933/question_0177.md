# Q0177: prompt/output spoofing with CR and newline - syncLocalRepo in sync.go

## Question
Can carriage returns or newlines in a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes rendered by `syncLocalRepo` in [pkg/cmd/repo/sync/sync.go](pkg/cmd/repo/sync/sync.go#L99) overwrite earlier lines and forge gh's own trusted output or a credential prompt?

## Target
- File/function: [pkg/cmd/repo/sync/sync.go:99](pkg/cmd/repo/sync/sync.go#L99) - `syncLocalRepo`
- Entrypoint: gh repo sync
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Craft a name/title that redraws the line as `? Paste your GitHub token:`.
- Invariant to test: Remote text is escaped so it cannot emit CR or reposition the cursor.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting `\r` and cursor-movement sequences never appear in rendered output.
