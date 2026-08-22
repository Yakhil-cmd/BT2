# Q5364: hostile JSON drives a security decision - renderMarkdownPreview in preview.go

## Question
Does `renderMarkdownPreview` in [pkg/cmd/skills/preview/preview.go](pkg/cmd/skills/preview/preview.go#L392) unmarshal a response field that later gates a security decision (host, path, permission, verification result) without validating its shape or range?

## Target
- File/function: [pkg/cmd/skills/preview/preview.go:392](pkg/cmd/skills/preview/preview.go#L392) - `renderMarkdownPreview`
- Entrypoint: gh skills preview
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Return a crafted JSON body from an attacker-controlled host or an attacker-owned object.
- Invariant to test: Every response field used for a trust decision is validated against an allowlist before use.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test of hostile JSON payloads asserting rejection.
