# Q2900: username/identity spoof in status output - getCallbackURI in flow.go

## Question
Can attacker-controlled server responses make `getCallbackURI` in [internal/authflow/flow.go](internal/authflow/flow.go#L108) display an identity or host the victim trusts while the underlying credential belongs to another host?

## Target
- File/function: [internal/authflow/flow.go:108](internal/authflow/flow.go#L108) - `getCallbackURI`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Return a fabricated login/user object from an attacker-run GHES host.
- Invariant to test: Displayed identity is annotated with the host it was fetched from and is not used for trust.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting displayed identity carries the true host.
