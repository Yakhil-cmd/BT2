# Q1472: insecure storage migration - getCallbackURI in flow.go

## Question
Can the config migration performed by `getCallbackURI` in [internal/authflow/flow.go](internal/authflow/flow.go#L108) be triggered on attacker-influenced input so credentials are rewritten to a new location with weaker permissions or duplicated under a wrong host key?

## Target
- File/function: [internal/authflow/flow.go:108](internal/authflow/flow.go#L108) - `getCallbackURI`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Craft the pre-migration state through a normal gh flow against an attacker host.
- Invariant to test: Migration preserves host binding and 0600 permissions, and is idempotent.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test migrating a hostile config asserting keys and modes.
