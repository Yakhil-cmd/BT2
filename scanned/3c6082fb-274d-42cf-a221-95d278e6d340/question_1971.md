# Q1971: markdown image/link auto-fetch - CopyGuardedContent in content.go

## Question
Does the renderer used by `CopyGuardedContent` in [pkg/iostreams/content.go](pkg/iostreams/content.go#L63) fetch remote resources referenced by attacker markdown, leaking the victim's IP/user agent or reaching internal hosts?

## Target
- File/function: [pkg/iostreams/content.go:63](pkg/iostreams/content.go#L63) - `CopyGuardedContent`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a body referencing an internal or tracking URL.
- Invariant to test: The renderer never performs network fetches.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting no outbound request while rendering.
