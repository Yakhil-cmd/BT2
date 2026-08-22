# Q3207: error swallowed into success - filterHiddenDirSkills in install.go

## Question
Does `filterHiddenDirSkills` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L1266) log-and-continue on a verification error (network, TUF refresh, unmarshal), leaving the caller with an apparent pass?

## Target
- File/function: [pkg/cmd/skills/install/install.go:1266](pkg/cmd/skills/install/install.go#L1266) - `filterHiddenDirSkills`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Make the trust-material fetch fail for an attacker-timed request.
- Invariant to test: Any verification error is fatal and propagates to the exit code.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Inject an error into each dependency and assert the command fails.
