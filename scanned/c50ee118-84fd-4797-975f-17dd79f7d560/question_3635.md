# Q3635: username/identity spoof in status output - (GitCredentialFlow).Prompt in git_credential.go

## Question
Can attacker-controlled server responses make `Prompt` in [pkg/cmd/auth/shared/git_credential.go](pkg/cmd/auth/shared/git_credential.go#L26) display an identity or host the victim trusts while the underlying credential belongs to another host?

## Target
- File/function: [pkg/cmd/auth/shared/git_credential.go:26](pkg/cmd/auth/shared/git_credential.go#L26) - `(GitCredentialFlow).Prompt`
- Entrypoint: gh auth
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Return a fabricated login/user object from an attacker-run GHES host.
- Invariant to test: Displayed identity is annotated with the host it was fetched from and is not used for trust.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting displayed identity carries the true host.
