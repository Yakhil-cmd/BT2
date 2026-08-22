# Q3434: markdown image/link auto-fetch - sortComments in comments.go

## Question
Does the renderer used by `sortComments` in [pkg/cmd/pr/shared/comments.go](pkg/cmd/pr/shared/comments.go#L144) fetch remote resources referenced by attacker markdown, leaking the victim's IP/user agent or reaching internal hosts?

## Target
- File/function: [pkg/cmd/pr/shared/comments.go:144](pkg/cmd/pr/shared/comments.go#L144) - `sortComments`
- Entrypoint: gh pr
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a body referencing an internal or tracking URL.
- Invariant to test: The renderer never performs network fetches.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting no outbound request while rendering.
