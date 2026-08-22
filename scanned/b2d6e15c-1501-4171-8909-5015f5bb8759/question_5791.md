# Q5791: host from override flag/env unchecked - CredentialPatternFromHost in client.go

## Question
Can a `-R OWNER/REPO`-style override or env-provided host flowing into `CredentialPatternFromHost` in [git/client.go](git/client.go#L134) redirect authenticated traffic to an unauthenticated or attacker host?

## Target
- File/function: [git/client.go:134](git/client.go#L134) - `CredentialPatternFromHost`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Get the victim to run a documented command form on attacker-supplied repo coordinates.
- Invariant to test: Overrides are parsed strictly and resolved against configured hosts before any request.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test of override strings asserting rejection of embedded hosts/URLs.
