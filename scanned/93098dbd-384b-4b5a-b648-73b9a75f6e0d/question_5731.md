# Q5731: host from override flag/env unchecked - NewCmdLogin in login.go

## Question
Can a `-R OWNER/REPO`-style override or env-provided host flowing into `NewCmdLogin` in [pkg/cmd/auth/login/login.go](pkg/cmd/auth/login/login.go#L45) redirect authenticated traffic to an unauthenticated or attacker host?

## Target
- File/function: [pkg/cmd/auth/login/login.go:45](pkg/cmd/auth/login/login.go#L45) - `NewCmdLogin`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Get the victim to run a documented command form on attacker-supplied repo coordinates.
- Invariant to test: Overrides are parsed strictly and resolved against configured hosts before any request.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test of override strings asserting rejection of embedded hosts/URLs.
