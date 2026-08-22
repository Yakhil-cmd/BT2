# Q1639: prompt/output spoofing with CR and newline - printLinkedBranches in develop.go

## Question
Can carriage returns or newlines in a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes rendered by `printLinkedBranches` in [pkg/cmd/issue/develop/develop.go](pkg/cmd/issue/develop/develop.go#L342) overwrite earlier lines and forge gh's own trusted output or a credential prompt?

## Target
- File/function: [pkg/cmd/issue/develop/develop.go:342](pkg/cmd/issue/develop/develop.go#L342) - `printLinkedBranches`
- Entrypoint: gh issue develop
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Craft a name/title that redraws the line as `? Paste your GitHub token:`.
- Invariant to test: Remote text is escaped so it cannot emit CR or reposition the cursor.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting `\r` and cursor-movement sequences never appear in rendered output.
