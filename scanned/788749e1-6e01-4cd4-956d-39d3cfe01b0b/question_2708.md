# Q2708: markdown image/link auto-fetch - printRawIssuePreview in view.go

## Question
Does the renderer used by `printRawIssuePreview` in [pkg/cmd/issue/view/view.go](pkg/cmd/issue/view/view.go#L197) fetch remote resources referenced by attacker markdown, leaking the victim's IP/user agent or reaching internal hosts?

## Target
- File/function: [pkg/cmd/issue/view/view.go:197](pkg/cmd/issue/view/view.go#L197) - `printRawIssuePreview`
- Entrypoint: gh issue view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a body referencing an internal or tracking URL.
- Invariant to test: The renderer never performs network fetches.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting no outbound request while rendering.
