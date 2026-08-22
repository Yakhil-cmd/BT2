# Q4805: pager/child renderer receives raw bytes - createGist in create.go

## Question
Does `createGist` in [pkg/cmd/gist/create/create.go](pkg/cmd/gist/create/create.go#L263) hand unsanitized remote text to a pager or external renderer where escape handling differs from gh's own?

## Target
- File/function: [pkg/cmd/gist/create/create.go:263](pkg/cmd/gist/create/create.go#L263) - `createGist`
- Entrypoint: gh gist create
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish content whose escapes are inert in gh but active in the pager.
- Invariant to test: Sanitization is applied before the bytes leave gh, regardless of the sink.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting the bytes written to a stub pager are already sanitized.
