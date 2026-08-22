# Q1729: ref name starting with a dash - IsFullyQualifiedRef in discovery.go

## Question
Does `IsFullyQualifiedRef` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L132) place a branch/ref/tag name from remote data in a git argv position where a leading `-` becomes an option (e.g. `--upload-pack=`)?

## Target
- File/function: [internal/skills/discovery/discovery.go:132](internal/skills/discovery/discovery.go#L132) - `IsFullyQualifiedRef`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a PR branch or tag named `--upload-pack=touch /tmp/pwn`.
- Invariant to test: Ref values are validated against git's ref format and always follow `--`.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table test with hostile ref names asserting rejection or correct positioning.
