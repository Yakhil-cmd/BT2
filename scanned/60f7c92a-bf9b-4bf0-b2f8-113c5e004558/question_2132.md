# Q2132: agent log stream rendered raw - putOrgSecret in http.go

## Question
Is the streamed agent/job log printed by `putOrgSecret` in [pkg/cmd/secret/set/http.go](pkg/cmd/secret/set/http.go#L85) sanitized, given its content derives from attacker-authored repository files and issue text?

## Target
- File/function: [pkg/cmd/secret/set/http.go:85](pkg/cmd/secret/set/http.go#L85) - `putOrgSecret`
- Entrypoint: gh secret set
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Get the payload into the log stream via repository content.
- Invariant to test: Streamed output is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile stream.
