# Q0351: identity matched by substring - filterHiddenDirSkills in install.go

## Question
Does the certificate identity check in `filterHiddenDirSkills` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L1266) use prefix/substring/regex matching so `github.com/victim-org/repo-evil` or an attacker fork satisfies a policy meant for `victim-org/repo`?

## Target
- File/function: [pkg/cmd/skills/install/install.go:1266](pkg/cmd/skills/install/install.go#L1266) - `filterHiddenDirSkills`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Build a real signed artifact from an attacker repository whose URL contains the expected string.
- Invariant to test: SAN, issuer, and source-repository claims are compared with exact, anchored equality.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Table test over near-miss identity URIs asserting each is rejected.
