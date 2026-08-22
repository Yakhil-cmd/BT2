# Q5593: host from override flag/env unchecked - ListenTCP in codespaces.go

## Question
Can a `-R OWNER/REPO`-style override or env-provided host flowing into `ListenTCP` in [internal/codespaces/codespaces.go](internal/codespaces/codespaces.go#L132) redirect authenticated traffic to an unauthenticated or attacker host?

## Target
- File/function: [internal/codespaces/codespaces.go:132](internal/codespaces/codespaces.go#L132) - `ListenTCP`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Get the victim to run a documented command form on attacker-supplied repo coordinates.
- Invariant to test: Overrides are parsed strictly and resolved against configured hosts before any request.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test of override strings asserting rejection of embedded hosts/URLs.
