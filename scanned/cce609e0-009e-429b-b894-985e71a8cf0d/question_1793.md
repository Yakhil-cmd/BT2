# Q1793: terminal command injection via escape - renderInteractive in preview.go

## Question
Can attacker-supplied text rendered by `renderInteractive` in [pkg/cmd/skills/preview/preview.go](pkg/cmd/skills/preview/preview.go#L318) carry sequences that terminals execute or auto-report (OSC 8 with a non-http URI, bracketed-paste break, title-set-then-report), turning display into command execution?

## Target
- File/function: [pkg/cmd/skills/preview/preview.go:318](pkg/cmd/skills/preview/preview.go#L318) - `renderInteractive`
- Entrypoint: gh skills preview
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Embed the payload in a PR title/body/check output the victim displays.
- Invariant to test: Only a safe subset of styling is emitted; hyperlinks are restricted to http(s).
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting rendered hyperlinks/URIs are scheme-checked and controls stripped.
