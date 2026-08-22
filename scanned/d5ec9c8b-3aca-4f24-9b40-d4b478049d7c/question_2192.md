# Q2192: username/identity spoof in status output - NewCmdLogout in logout.go

## Question
Can attacker-controlled server responses make `NewCmdLogout` in [pkg/cmd/auth/logout/logout.go](pkg/cmd/auth/logout/logout.go#L24) display an identity or host the victim trusts while the underlying credential belongs to another host?

## Target
- File/function: [pkg/cmd/auth/logout/logout.go:24](pkg/cmd/auth/logout/logout.go#L24) - `NewCmdLogout`
- Entrypoint: gh auth logout
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Return a fabricated login/user object from an attacker-run GHES host.
- Invariant to test: Displayed identity is annotated with the host it was fetched from and is not used for trust.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting displayed identity carries the true host.
