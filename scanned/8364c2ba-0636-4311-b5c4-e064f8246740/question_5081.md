# Q5081: prompt/output spoofing with CR and newline - AddCacheTTLHeader in http_client.go

## Question
Can carriage returns or newlines in a repo/remote/host string or API response field the attacker publishes rendered by `AddCacheTTLHeader` in [api/http_client.go](api/http_client.go#L141) overwrite earlier lines and forge gh's own trusted output or a credential prompt?

## Target
- File/function: [api/http_client.go:141](api/http_client.go#L141) - `AddCacheTTLHeader`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Craft a name/title that redraws the line as `? Paste your GitHub token:`.
- Invariant to test: Remote text is escaped so it cannot emit CR or reposition the cursor.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting `\r` and cursor-movement sequences never appear in rendered output.
