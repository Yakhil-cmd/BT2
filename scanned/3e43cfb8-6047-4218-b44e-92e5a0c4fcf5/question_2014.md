# Q2014: markdown image/link auto-fetch - parseFile in browse.go

## Question
Does the renderer used by `parseFile` in [pkg/cmd/browse/browse.go](pkg/cmd/browse/browse.go#L302) fetch remote resources referenced by attacker markdown, leaking the victim's IP/user agent or reaching internal hosts?

## Target
- File/function: [pkg/cmd/browse/browse.go:302](pkg/cmd/browse/browse.go#L302) - `parseFile`
- Entrypoint: gh browse browse
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a body referencing an internal or tracking URL.
- Invariant to test: The renderer never performs network fetches.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting no outbound request while rendering.
