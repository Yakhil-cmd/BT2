# Q4912: pager/child renderer receives raw bytes - (API).GetCodespaceRepoSuggestions in api.go

## Question
Does `GetCodespaceRepoSuggestions` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L754) hand unsanitized remote text to a pager or external renderer where escape handling differs from gh's own?

## Target
- File/function: [internal/codespaces/api/api.go:754](internal/codespaces/api/api.go#L754) - `(API).GetCodespaceRepoSuggestions`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish content whose escapes are inert in gh but active in the pager.
- Invariant to test: Sanitization is applied before the bytes leave gh, regardless of the sink.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting the bytes written to a stub pager are already sanitized.
