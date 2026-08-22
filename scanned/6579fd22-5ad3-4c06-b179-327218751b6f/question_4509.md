# Q4509: extension name validation bypass - (Manager).upgradeExtensions in manager.go

## Question
Can the name validation in `upgradeExtensions` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L487) be bypassed with unicode, case, or separator tricks so the created directory or dispatch key differs from what was shown to the user?

## Target
- File/function: [pkg/cmd/extension/manager.go:487](pkg/cmd/extension/manager.go#L487) - `(Manager).upgradeExtensions`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish `gh-Auth` or a homoglyph variant.
- Invariant to test: Names are normalized and validated against a strict character set once.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table test over hostile names asserting normalization and rejection.
