# Q0560: markdown image/link auto-fetch - parseReviewers in view.go

## Question
Does the renderer used by `parseReviewers` in [pkg/cmd/pr/view/view.go](pkg/cmd/pr/view/view.go#L349) fetch remote resources referenced by attacker markdown, leaking the victim's IP/user agent or reaching internal hosts?

## Target
- File/function: [pkg/cmd/pr/view/view.go:349](pkg/cmd/pr/view/view.go#L349) - `parseReviewers`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a body referencing an internal or tracking URL.
- Invariant to test: The renderer never performs network fetches.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting no outbound request while rendering.
