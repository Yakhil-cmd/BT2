# Q0068: checkout of attacker-controlled path or worktree - (HelperConfig).ConfiguredHelper in helper_config.go

## Question
Can a branch/PR name reaching `ConfiguredHelper` in [pkg/cmd/auth/shared/gitcredentials/helper_config.go](pkg/cmd/auth/shared/gitcredentials/helper_config.go#L92) determine a worktree or directory path, letting the checkout land outside the repository?

## Target
- File/function: [pkg/cmd/auth/shared/gitcredentials/helper_config.go:92](pkg/cmd/auth/shared/gitcredentials/helper_config.go#L92) - `(HelperConfig).ConfiguredHelper`
- Entrypoint: gh auth
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish a PR whose head ref contains traversal segments.
- Invariant to test: Derived paths are sanitized and confined to the repo/worktree root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test over hostile ref names asserting the resolved path stays inside the root.
