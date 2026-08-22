# Q5356: hostile JSON drives a security decision - parseInstalledSkill in update.go

## Question
Does `parseInstalledSkill` in [pkg/cmd/skills/update/update.go](pkg/cmd/skills/update/update.go#L601) unmarshal a response field that later gates a security decision (host, path, permission, verification result) without validating its shape or range?

## Target
- File/function: [pkg/cmd/skills/update/update.go:601](pkg/cmd/skills/update/update.go#L601) - `parseInstalledSkill`
- Entrypoint: gh skills update
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Return a crafted JSON body from an attacker-controlled host or an attacker-owned object.
- Invariant to test: Every response field used for a trust decision is validated against an allowlist before use.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test of hostile JSON payloads asserting rejection.
